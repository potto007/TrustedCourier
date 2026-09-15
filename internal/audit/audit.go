// Package audit keeps the Audit Records: one per Delivery attempt, appended
// to SQLite, hash-chained, and streamed as JSON lines (ADR-0007, ADR-0016).
package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/potto007/TrustedCourier/internal/config"
)

// Decision is a Delivery attempt's Policy decision.
type Decision string

// Decisions.
const (
	Allowed Decision = "allowed"
	Denied  Decision = "denied"
)

// Record is what an Audit Record says about one Delivery attempt. It never
// holds a Secret's value or a request or response body.
type Record struct {
	AgentTokenID string
	SecretName   string
	Delivery     config.DeliveryMode
	// Upstream is the Upstream name a Proxy Delivery asked for, and
	// UpstreamHost the host it is pinned to, when there is one.
	Upstream     string
	UpstreamHost string
	Decision     Decision
	// Reason is why the attempt was denied.
	Reason string
	// UpstreamStatus is the status code of the Upstream's response, or 0
	// when there was none.
	UpstreamStatus int
	// Failure is why an allowed Delivery did not complete.
	Failure string
}

// entry is an Audit Record as it is hashed and streamed. Its JSON encoding,
// without Hash, is what the hash covers, so its fields and their order are
// part of the chain's format.
type entry struct {
	Seq            int64  `json:"seq"`
	Time           string `json:"time"`
	AgentTokenID   string `json:"agent_token_id"`
	SecretName     string `json:"secret_name"`
	Delivery       string `json:"delivery"`
	Upstream       string `json:"upstream"`
	UpstreamHost   string `json:"upstream_host"`
	Decision       string `json:"decision"`
	Reason         string `json:"reason"`
	UpstreamStatus *int   `json:"upstream_status"`
	Failure        string `json:"failure"`
	PrevHash       string `json:"prev_hash"`
	Hash           string `json:"hash,omitempty"`
}

// timeFormat is RFC 3339 at the millisecond precision records are stored at.
const timeFormat = "2006-01-02T15:04:05.000Z07:00"

// hash returns the SHA-256 of e without its Hash.
func (e entry) hash() ([]byte, error) {
	e.Hash = ""
	data, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	return sum[:], nil
}

// Log appends Audit Records. It is safe for concurrent use.
type Log struct {
	db     *sql.DB
	stream io.Writer
	now    func() time.Time

	mu sync.Mutex
	// seq and head are the last record appended: its sequence number and
	// hash. The next record chains to them.
	seq  int64
	head []byte
}

// genesis is the previous hash of the first record.
var genesis = make([]byte, sha256.Size)

// Open returns a Log over db that streams each record to stream after it is
// stored.
func Open(ctx context.Context, db *sql.DB, stream io.Writer) (*Log, error) {
	l := &Log{db: db, stream: stream, now: time.Now, head: genesis}
	err := db.QueryRowContext(ctx, "SELECT seq, hash FROM audit_records ORDER BY seq DESC LIMIT 1").Scan(&l.seq, &l.head)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("read the audit chain head: %w", err)
	}
	return l, nil
}

// Append stores r as the next Audit Record, then streams it.
func (l *Log) Append(ctx context.Context, r Record) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now().UnixMilli()
	e := newEntry(l.seq+1, now, r, l.head)
	sum, err := e.hash()
	if err != nil {
		return err
	}
	var status sql.NullInt64
	if e.UpstreamStatus != nil {
		status = sql.NullInt64{Int64: int64(*e.UpstreamStatus), Valid: true}
	}
	if _, err := l.db.ExecContext(ctx,
		`INSERT INTO audit_records (seq, time, agent_token_id, secret_name, delivery, upstream,
		 upstream_host, decision, reason, upstream_status, failure, prev_hash, hash)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.Seq, now, e.AgentTokenID, e.SecretName, e.Delivery, e.Upstream,
		e.UpstreamHost, e.Decision, e.Reason, status, e.Failure, l.head, sum); err != nil {
		return fmt.Errorf("store Audit Record: %w", err)
	}
	l.seq, l.head = e.Seq, sum

	e.Hash = hex.EncodeToString(sum)
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if _, err := l.stream.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("stream Audit Record %d: %w", e.Seq, err)
	}
	return nil
}

func newEntry(seq, ms int64, r Record, prevHash []byte) entry {
	e := entry{
		Seq:          seq,
		Time:         time.UnixMilli(ms).UTC().Format(timeFormat),
		AgentTokenID: r.AgentTokenID,
		SecretName:   r.SecretName,
		Delivery:     string(r.Delivery),
		Upstream:     r.Upstream,
		UpstreamHost: r.UpstreamHost,
		Decision:     string(r.Decision),
		Reason:       r.Reason,
		Failure:      r.Failure,
		PrevHash:     hex.EncodeToString(prevHash),
	}
	if r.UpstreamStatus != 0 {
		e.UpstreamStatus = &r.UpstreamStatus
	}
	return e
}

// Verification is the result of checking the audit chain.
type Verification struct {
	// Records is how many records were found intact before the first break,
	// or in all when there is none.
	Records int64
	// Break is the first break in the chain, or nil when it is intact.
	Break *Break
}

// Break is the first place the audit chain does not hold.
type Break struct {
	// Seq is the sequence number of the missing or failing record.
	Seq     int64
	Problem string
}

// verifyPage bounds how many records Verify reads in one query, so a long
// chain does not hold the database connection Deliveries also need.
const verifyPage = 1000

// Verify walks the chain in SQLite from its first record and reports the first
// break: a missing record, a record that no longer matches its hash, or one
// that does not chain to the record before it. It also reports records this
// process appended that have since been removed from the end of the chain or
// replaced there.
func (l *Log) Verify(ctx context.Context) (Verification, error) {
	l.mu.Lock()
	headSeq, head := l.seq, l.head
	l.mu.Unlock()

	var v Verification
	prev := genesis
	for {
		n, err := l.verifyPage(ctx, &v, &prev, headSeq, head)
		if err != nil || v.Break != nil {
			return v, err
		}
		if n < verifyPage {
			break
		}
	}
	if v.Records < headSeq {
		v.Break = &Break{Seq: v.Records + 1, Problem: fmt.Sprintf("record %d is missing", v.Records+1)}
	}
	return v, nil
}

// verifyPage checks the records after v.Records, up to verifyPage of them,
// and returns how many it read.
func (l *Log) verifyPage(ctx context.Context, v *Verification, prev *[]byte, headSeq int64, head []byte) (int, error) {
	rows, err := l.db.QueryContext(ctx,
		`SELECT seq, time, agent_token_id, secret_name, delivery, upstream, upstream_host,
		 decision, reason, upstream_status, failure, prev_hash, hash
		 FROM audit_records WHERE seq > ? ORDER BY seq LIMIT ?`, v.Records, verifyPage)
	if err != nil {
		return 0, fmt.Errorf("read Audit Records: %w", err)
	}
	defer func() { _ = rows.Close() }()

	n := 0
	for rows.Next() {
		n++
		var (
			r                    Record
			seq, ms              int64
			status               sql.NullInt64
			prevHash, storedHash []byte
		)
		if err := rows.Scan(&seq, &ms, &r.AgentTokenID, &r.SecretName, &r.Delivery, &r.Upstream,
			&r.UpstreamHost, &r.Decision, &r.Reason, &status, &r.Failure, &prevHash, &storedHash); err != nil {
			return n, fmt.Errorf("read Audit Record: %w", err)
		}
		r.UpstreamStatus = int(status.Int64)
		sum, err := newEntry(seq, ms, r, prevHash).hash()
		if err != nil {
			return n, err
		}
		want := v.Records + 1
		switch {
		case seq != want:
			v.Break = &Break{Seq: want, Problem: fmt.Sprintf("record %d is missing", want)}
		case !bytes.Equal(sum, storedHash):
			v.Break = &Break{Seq: seq, Problem: fmt.Sprintf("record %d does not match its hash", seq)}
		case !bytes.Equal(prevHash, *prev):
			v.Break = &Break{Seq: seq, Problem: fmt.Sprintf("record %d does not chain to the record before it", seq)}
		case seq == headSeq && !bytes.Equal(storedHash, head):
			v.Break = &Break{Seq: seq, Problem: fmt.Sprintf("record %d is not the record TrustedCourier appended", seq)}
		}
		if v.Break != nil {
			return n, nil
		}
		v.Records, *prev = seq, storedHash
	}
	return n, rows.Err()
}
