//go:build race

package harness

// raceEnabled builds tc with the race detector when the tests run with -race.
const raceEnabled = true
