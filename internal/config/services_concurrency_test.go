package config

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

func TestServiceStoreCreateAtomicConcurrency(t *testing.T) {
	st := OpenServiceStore(t.TempDir())

	// 1) 16 goroutines racing to create the exact same name: exactly 1 MUST succeed.
	const n = 16
	var wg sync.WaitGroup
	var okCount, dupCount, otherErr atomic.Int32
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, err := st.CreateAtomic(ServiceRecord{
				Name:        "myapp",
				Type:        "http",
				BackendMode: BackendAttached,
				LocalURL:    "http://127.0.0.1:3000",
			})
			switch {
			case err == nil:
				okCount.Add(1)
			case errors.Is(err, ErrServiceAlreadyExists):
				dupCount.Add(1)
			default:
				otherErr.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if okCount.Load() != 1 || dupCount.Load() != n-1 || otherErr.Load() != 0 {
		t.Fatalf("same-name race: ok=%d dup=%d other=%d (want 1, %d, 0)", okCount.Load(), dupCount.Load(), otherErr.Load(), n-1)
	}

	// 2) 16 goroutines racing to create "Foo" vs "foo": at most 1 MUST succeed.
	st2 := OpenServiceStore(t.TempDir())
	var okCase, conflictCase, otherCase atomic.Int32
	for i := 0; i < n; i++ {
		wg.Add(1)
		name := "Foo"
		if i%2 == 1 {
			name = "foo"
		}
		go func(nm string) {
			defer wg.Done()
			_, err := st2.CreateAtomic(ServiceRecord{
				Name:        nm,
				Type:        "http",
				BackendMode: BackendAttached,
				LocalURL:    "http://127.0.0.1:3001",
			})
			switch {
			case err == nil:
				okCase.Add(1)
			case errors.Is(err, ErrServiceAlreadyExists) || errors.Is(err, ErrServiceLabelCollision):
				conflictCase.Add(1)
			default:
				otherCase.Add(1)
			}
		}(name)
	}
	wg.Wait()
	if okCase.Load() != 1 || conflictCase.Load() != n-1 || otherCase.Load() != 0 {
		t.Fatalf("case-collision race: ok=%d conflict=%d other=%d (want 1, %d, 0)", okCase.Load(), conflictCase.Load(), otherCase.Load(), n-1)
	}
	recs, err := st2.List()
	if err != nil || len(recs) != 1 {
		t.Fatalf("expected exactly 1 persisted record after Foo/foo race, got %d err=%v", len(recs), err)
	}
}
