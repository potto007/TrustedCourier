// Package audit keeps the Audit Records: one per Delivery attempt, appended
// to SQLite, hash-chained, streamed as JSON lines, and covered by checkpoints
// signed with the audit signing key (ADR-0007, ADR-0016, ADR-0019).
package audit

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/potto007/TrustedCourier/internal/config"
	"github.com/potto007/TrustedCourier/internal/secret"
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

// checkpoint is a signed statement that the chain's record seq has hash
// head, and that the checkpoint before it covered record prevSeq.
type checkpoint struct {
	seq, prevSeq, ms int64
	head             []byte
}

// checkpointContext starts every signed message, so the audit signing key's
// signatures cannot be mistaken for anything else.
const checkpointContext = "TrustedCourier audit checkpoint\x00"

// message returns what the checkpoint's signature covers: the context, then
// seq, prevSeq, and the time in Unix milliseconds as big-endian 64-bit
// integers, then head.
func (c checkpoint) message() []byte {
	msg := make([]byte, 0, len(checkpointContext)+3*8+sha256.Size)
	msg = append(msg, checkpointContext...)
	msg = binary.BigEndian.AppendUint64(msg, uint64(c.seq))
	msg = binary.BigEndian.AppendUint64(msg, uint64(c.prevSeq))
	msg = binary.BigEndian.AppendUint64(msg, uint64(c.ms))
	return append(msg, c.head...)
}

// Checkpoints is how often the chain head is signed.
type Checkpoints struct {
	// Records is how many records may follow the last checkpoint before the
	// next is signed.
	Records int
	// Interval is how long a record may go unsigned.
	Interval time.Duration
}

// FetchKey fetches the audit signing key from its Backend. The caller
// releases the Secret.
type FetchKey func(context.Context) (*secret.Secret, error)

// How long loading the audit signing key waits between attempts.
const (
	minKeyRetry = 250 * time.Millisecond
	maxKeyRetry = 5 * time.Second
)

// ErrNoSigningKey reports that the audit signing key is not loaded.
var ErrNoSigningKey = errors.New("the audit signing key is not loaded, so the signed checkpoints cannot be verified; tc status says why")

// Why Ready refuses Deliveries.
var (
	ErrKeyNotLoaded = errors.New("the audit signing key is not loaded")
	ErrNotStoring   = errors.New("Audit Records cannot be stored")
)

// pending is an Audit Record waiting to be stored, with the time it was
// made.
type pending struct {
	r  Record
	ms int64
}

// Log appends Audit Records and signs checkpoints. It is safe for concurrent
// use.
type Log struct {
	db          *sql.DB
	stream      io.Writer
	now         func() time.Time
	checkpoints Checkpoints
	log         *slog.Logger

	mu sync.Mutex
	// seq and head are the last record appended: its sequence number and
	// hash. The next record chains to them.
	seq  int64
	head []byte
	// cpSeq is the record the last checkpoint covers, or 0 before the first.
	// The next checkpoint names it.
	cpSeq int64
	// key signs checkpoints. Nil until loaded; keyDetail says why.
	key       *secret.Ed25519Key
	keyDetail string
	// backlog holds the records not yet stored, oldest first, and storeErr
	// why the oldest could not be.
	backlog  []pending
	storeErr string

	// keyLoaded is set once key is loaded, and backlogged while backlog is
	// not empty, so Ready never waits on mu.
	keyLoaded  atomic.Bool
	backlogged atomic.Bool
	// ctx ends when Close is called, stopping background work.
	ctx  context.Context
	stop context.CancelFunc
	wg   sync.WaitGroup
}

// genesis is the previous hash of the first record.
var genesis = make([]byte, sha256.Size)

// Open returns a Log over db that streams each record to stream after it is
// stored and signs checkpoints as often as checkpoints says, once Start has
// loaded the audit signing key.
func Open(ctx context.Context, db *sql.DB, stream io.Writer, checkpoints Checkpoints, log *slog.Logger) (*Log, error) {
	l := &Log{db: db, stream: stream, now: time.Now, checkpoints: checkpoints, log: log, head: genesis, keyDetail: "not configured"}
	l.ctx, l.stop = context.WithCancel(context.Background())
	err := db.QueryRowContext(ctx, "SELECT seq, hash FROM audit_records ORDER BY seq DESC LIMIT 1").Scan(&l.seq, &l.head)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("read the audit chain head: %w", err)
	}
	err = db.QueryRowContext(ctx, "SELECT seq FROM audit_checkpoints ORDER BY seq DESC LIMIT 1").Scan(&l.cpSeq)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("read the last audit checkpoint: %w", err)
	}
	return l, nil
}

// Start loads the audit signing key with fetch in the background, retrying
// until it succeeds or Close is called, then signs a checkpoint every
// Interval while records are waiting for one. Call it at most once.
func (l *Log) Start(fetch FetchKey) {
	l.mu.Lock()
	l.keyDetail = "loading"
	l.mu.Unlock()
	l.wg.Go(func() {
		if l.loadKey(l.ctx, fetch) {
			l.signEveryInterval(l.ctx)
		}
	})
}

// Ready returns nil when Deliveries may be served: the audit signing key is
// loaded and every Audit Record so far is stored. Otherwise it returns
// ErrKeyNotLoaded or ErrNotStoring.
func (l *Log) Ready() error {
	switch {
	case !l.keyLoaded.Load():
		return ErrKeyNotLoaded
	case l.backlogged.Load():
		return ErrNotStoring
	}
	return nil
}

// Backlog reports how many Audit Records are waiting to be stored, and why
// the oldest could not be.
func (l *Log) Backlog() (pending int, detail string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.backlog), l.storeErr
}

// KeyStatus reports whether the audit signing key is loaded, and why not when
// it is not.
func (l *Log) KeyStatus() (loaded bool, detail string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.key != nil, l.keyDetail
}

// loadKey fetches and parses the audit signing key until it succeeds, and
// reports false if ctx ends first.
func (l *Log) loadKey(ctx context.Context, fetch FetchKey) bool {
	retry := minKeyRetry
	for {
		key, err := parseKey(ctx, fetch)
		if err == nil {
			l.mu.Lock()
			l.key, l.keyDetail = key, ""
			l.mu.Unlock()
			l.keyLoaded.Store(true)
			l.log.Info("audit signing key loaded")
			return true
		}
		if ctx.Err() != nil {
			return false
		}
		l.mu.Lock()
		l.keyDetail = err.Error()
		l.mu.Unlock()
		l.log.Warn("audit signing key not loaded; Deliveries are refused until it is", "error", err, "retry_in", retry)
		select {
		case <-ctx.Done():
			return false
		case <-time.After(retry):
		}
		retry = min(retry*2, maxKeyRetry)
	}
}

func parseKey(ctx context.Context, fetch FetchKey) (*secret.Ed25519Key, error) {
	s, err := fetch(ctx)
	if err != nil {
		return nil, err
	}
	defer s.Release()
	return secret.ParseEd25519Key(s)
}

// signEveryInterval signs a checkpoint every Interval when records are
// waiting for one, until ctx ends.
func (l *Log) signEveryInterval(ctx context.Context) {
	tick := time.NewTicker(l.checkpoints.Interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		l.mu.Lock()
		err := l.checkpoint(context.WithoutCancel(ctx))
		l.mu.Unlock()
		if err != nil {
			l.log.Error("audit checkpoint failed", "error", err)
		}
	}
}

// Close stops background work, makes a last attempt to store any records
// waiting to be, logging each that still cannot be, signs a checkpoint for
// any records waiting for one, and releases the key. Call it once nothing
// appends any more, before db closes.
func (l *Log) Close() error {
	l.stop()
	l.wg.Wait()
	l.keyLoaded.Store(false)
	l.mu.Lock()
	defer l.mu.Unlock()
	storeErr := l.flush(context.Background())
	if len(l.backlog) > 0 {
		// Records hold no Secret values, so the log is a safe last resort.
		for _, p := range l.backlog {
			line, _ := json.Marshal(newEntry(0, p.ms, p.r, nil))
			l.log.Error("Audit Record lost at shutdown: it could not be stored", "record", string(line))
		}
		storeErr = fmt.Errorf("%d Audit Records lost at shutdown: %w", len(l.backlog), storeErr)
	}
	if l.key == nil {
		return storeErr
	}
	err := l.checkpoint(context.Background())
	l.key.Release()
	l.key, l.keyDetail = nil, "released at shutdown"
	return errors.Join(storeErr, err)
}

// checkpoint signs and stores a checkpoint of the chain head when the key is
// loaded and records follow the last checkpoint. l.mu must be held.
func (l *Log) checkpoint(ctx context.Context) error {
	if l.key == nil || l.seq <= l.cpSeq {
		return nil
	}
	c := checkpoint{seq: l.seq, prevSeq: l.cpSeq, ms: l.now().UnixMilli(), head: l.head}
	sig, err := l.key.Sign(c.message())
	if err != nil {
		return fmt.Errorf("sign the checkpoint at Audit Record %d: %w", c.seq, err)
	}
	if _, err := l.db.ExecContext(ctx,
		"INSERT INTO audit_checkpoints (seq, prev_seq, time, head, signature) VALUES (?, ?, ?, ?, ?)",
		c.seq, c.prevSeq, c.ms, c.head, sig); err != nil {
		return fmt.Errorf("store the checkpoint at Audit Record %d: %w", c.seq, err)
	}
	l.cpSeq = c.seq
	return nil
}

// Append stores r as the next Audit Record, streams it, and signs a
// checkpoint when Records records follow the last one.
//
// When r cannot be stored, it waits in memory with every later record, and
// Ready refuses Deliveries until all of them are stored, in order, by a
// background retry or a later Append.
func (l *Log) Append(ctx context.Context, r Record) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.backlog = append(l.backlog, pending{r: r, ms: l.now().UnixMilli()})
	return l.flush(ctx)
}

// How long a retry of records that could not be stored waits.
const (
	minStoreRetry = 250 * time.Millisecond
	maxStoreRetry = 5 * time.Second
)

// flush stores the backlog in order, stopping at the first record that
// cannot be stored. l.mu must be held.
func (l *Log) flush(ctx context.Context) error {
	var errs []error
	for len(l.backlog) > 0 {
		err := l.store(ctx, l.backlog[0])
		var stored *storedError
		if err != nil && !errors.As(err, &stored) {
			l.storeErr = err.Error()
			if !l.backlogged.Swap(true) {
				l.log.Error("Audit Records cannot be stored; Deliveries are refused until they are", "error", err)
				if l.ctx.Err() == nil {
					l.wg.Go(l.retryStore)
				}
			}
			return errors.Join(append(errs, err)...)
		}
		l.backlog = l.backlog[1:]
		errs = append(errs, err)
	}
	l.storeErr = ""
	if l.backlogged.Swap(false) {
		l.log.Info("Audit Records stored again; Deliveries resume")
	}
	return errors.Join(errs...)
}

// retryStore flushes the backlog with backoff until it is empty or Close is
// called.
func (l *Log) retryStore() {
	retry := minStoreRetry
	for {
		select {
		case <-l.ctx.Done():
			return
		case <-time.After(retry):
		}
		l.mu.Lock()
		_ = l.flush(context.Background())
		done := len(l.backlog) == 0
		l.mu.Unlock()
		if done {
			return
		}
		retry = min(retry*2, maxStoreRetry)
	}
}

// storedError is a failure after a record was stored, such as streaming it.
type storedError struct{ err error }

func (e *storedError) Error() string { return e.err.Error() }
func (e *storedError) Unwrap() error { return e.err }

// store stores p as the next record, streams it, and signs a checkpoint when
// one is due. An error after the record is stored is a *storedError. l.mu
// must be held.
func (l *Log) store(ctx context.Context, p pending) error {
	now := p.ms
	e := newEntry(l.seq+1, now, p.r, l.head)
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
	var streamErr, checkpointErr error
	if line, err := json.Marshal(e); err != nil {
		streamErr = fmt.Errorf("Audit Record %d stored but not streamed: %w", e.Seq, err)
	} else if _, err := l.stream.Write(append(line, '\n')); err != nil {
		streamErr = fmt.Errorf("Audit Record %d stored but not streamed: %w", e.Seq, err)
	}
	// A failed checkpoint is retried on the next append.
	if l.seq-l.cpSeq >= int64(l.checkpoints.Records) {
		checkpointErr = l.checkpoint(ctx)
	}
	if err := errors.Join(streamErr, checkpointErr); err != nil {
		return &storedError{err}
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
	// or in all when there is none. After a break in the signed checkpoints,
	// it counts only the records the last good checkpoint covers.
	Records int64
	// Checkpoints is how many signed checkpoints verified.
	Checkpoints int64
	// Break is the first break in the chain, or nil when it is intact.
	Break *Break
}

// Break is the first place the audit chain does not hold.
type Break struct {
	// Seq is the sequence number of the missing or failing record, or of the
	// record a missing or failing checkpoint covers.
	Seq     int64
	Problem string
}

// verifyPage bounds how many records or checkpoints Verify reads in one
// query, so a long chain does not hold the database connection Deliveries
// also need.
const verifyPage = 1000

// walk is how far Verify has checked the chain and its checkpoints.
type walk struct {
	v Verification
	// prev is the hash of record v.Records.
	prev []byte
	// cpSeq is the record the last verified checkpoint covers.
	cpSeq  int64
	public ed25519.PublicKey
}

// Verify walks the chain in SQLite from its first record and reports the first
// break: a missing record, a record that no longer matches its hash, one that
// does not chain to the record before it, or a signed checkpoint that is
// missing, does not verify with the audit signing key, or does not match the
// record it covers. It also compares the chain's end with the last record and
// checkpoint this process wrote, so records removed or replaced there, or
// written after it by anyone else, are reported too.
func (l *Log) Verify(ctx context.Context) (Verification, error) {
	l.mu.Lock()
	key := l.key
	l.mu.Unlock()
	if key == nil {
		return Verification{}, ErrNoSigningKey
	}
	w := &walk{prev: genesis, public: key.Public()}
	// Walk most of the chain while Deliveries go on appending, then the rest
	// under the lock, where the end cannot move.
	if err := l.walk(ctx, w); err != nil || w.v.Break != nil {
		return w.v, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.walk(ctx, w); err != nil || w.v.Break != nil {
		return w.v, err
	}

	// A checkpoint past the chain's end covers records that are gone.
	var covering int64
	err := l.db.QueryRowContext(ctx, "SELECT seq FROM audit_checkpoints WHERE seq > ? ORDER BY seq LIMIT 1", w.v.Records).Scan(&covering)
	switch {
	case err == nil:
		missing := w.v.Records + 1
		w.v.Break = &Break{Seq: missing, Problem: fmt.Sprintf("record %d is missing; the signed checkpoint at record %d covers it", missing, covering)}
		return w.v, nil
	case !errors.Is(err, sql.ErrNoRows):
		return w.v, fmt.Errorf("read audit checkpoints: %w", err)
	}

	v := &w.v
	switch {
	case v.Records < l.seq:
		v.Break = &Break{Seq: v.Records + 1, Problem: fmt.Sprintf("record %d is missing", v.Records+1)}
	case v.Records > l.seq:
		v.Records = l.seq
		v.Break = &Break{Seq: l.seq + 1, Problem: fmt.Sprintf("record %d was not appended by TrustedCourier", l.seq+1)}
	case !bytes.Equal(w.prev, l.head):
		v.Records = l.seq - 1
		v.Break = &Break{Seq: l.seq, Problem: fmt.Sprintf("record %d is not the record TrustedCourier appended", l.seq)}
	case w.cpSeq < l.cpSeq:
		v.Records = w.cpSeq
		v.Break = &Break{Seq: l.cpSeq, Problem: fmt.Sprintf("the signed checkpoint at record %d is missing", l.cpSeq)}
	}
	return *v, nil
}

// walk checks the records after w's end, then the checkpoints covering the
// records found intact. A checkpoint break comes before any record break,
// since it covers only intact records, so it is the one reported.
func (l *Log) walk(ctx context.Context, w *walk) error {
	if err := l.verifyRest(ctx, &w.v, &w.prev); err != nil {
		return err
	}
	recordBreak := w.v.Break
	w.v.Break = nil
	for {
		n, err := l.verifyCheckpointPage(ctx, w)
		if err != nil {
			return err
		}
		if w.v.Break != nil {
			return nil
		}
		if n < verifyPage {
			w.v.Break = recordBreak
			return nil
		}
	}
}

// verifyCheckpointPage checks the checkpoints after w.cpSeq that cover
// records up to w.v.Records, up to verifyPage of them, and returns how many it
// read.
func (l *Log) verifyCheckpointPage(ctx context.Context, w *walk) (int, error) {
	rows, err := l.db.QueryContext(ctx,
		`SELECT c.seq, c.prev_seq, c.time, c.head, c.signature, r.hash
		 FROM audit_checkpoints c LEFT JOIN audit_records r ON r.seq = c.seq
		 WHERE c.seq > ? AND c.seq <= ? ORDER BY c.seq LIMIT ?`, w.cpSeq, w.v.Records, verifyPage)
	if err != nil {
		return 0, fmt.Errorf("read audit checkpoints: %w", err)
	}
	defer func() { _ = rows.Close() }()

	n := 0
	for rows.Next() {
		n++
		var (
			c               checkpoint
			sig, recordHash []byte
		)
		if err := rows.Scan(&c.seq, &c.prevSeq, &c.ms, &c.head, &sig, &recordHash); err != nil {
			return n, fmt.Errorf("read audit checkpoint: %w", err)
		}
		var b *Break
		switch {
		case !ed25519.Verify(w.public, c.message(), sig):
			b = &Break{Seq: c.seq, Problem: fmt.Sprintf("the signed checkpoint at record %d does not verify with the audit signing key", c.seq)}
		case c.prevSeq > w.cpSeq:
			b = &Break{Seq: c.prevSeq, Problem: fmt.Sprintf("the signed checkpoint at record %d is missing", c.prevSeq)}
		case c.prevSeq < w.cpSeq:
			b = &Break{Seq: c.seq, Problem: fmt.Sprintf("the signed checkpoint at record %d does not follow the one at record %d", c.seq, w.cpSeq)}
		case !bytes.Equal(c.head, recordHash):
			b = &Break{Seq: c.seq, Problem: fmt.Sprintf("record %d does not match its signed checkpoint", c.seq)}
		}
		if b != nil {
			w.v.Break, w.v.Records = b, w.cpSeq
			return n, nil
		}
		w.cpSeq = c.seq
		w.v.Checkpoints++
	}
	return n, rows.Err()
}

// verifyRest checks the records after v.Records, page by page, until it
// reaches the end of the chain or a break.
func (l *Log) verifyRest(ctx context.Context, v *Verification, prev *[]byte) error {
	for {
		n, err := l.verifyPage(ctx, v, prev)
		if err != nil || v.Break != nil || n < verifyPage {
			return err
		}
	}
}

// verifyPage checks the records after v.Records, up to verifyPage of them,
// and returns how many it read.
func (l *Log) verifyPage(ctx context.Context, v *Verification, prev *[]byte) (int, error) {
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
		}
		if v.Break != nil {
			return n, nil
		}
		v.Records, *prev = seq, storedHash
	}
	return n, rows.Err()
}
