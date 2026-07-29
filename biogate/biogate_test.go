package biogate

import (
	"context"
	"testing"
	"time"
)

const mMock Method = "mock"

type mockApprover struct{ err error }

func (m mockApprover) Method() Method                       { return mMock }
func (m mockApprover) Approve(context.Context, Request) error { return m.err }

func TestRequireApprovalSignsAndVerifies(t *testing.T) {
	tok, err := RequireApproval(context.Background(),
		Request{Action: "launch", Subject: "claude-code", Detail: "test", Methods: []Method{mMock}},
		WithApprover(mockApprover{}),
		WithClock(func() time.Time { return time.Unix(1700000000, 0) }),
	)
	if err != nil {
		t.Fatalf("RequireApproval: %v", err)
	}
	if tok.Action != "launch" || tok.Subject != "claude-code" || tok.Method != mMock {
		t.Fatalf("token fields wrong: %+v", tok)
	}
	if err := Verify(tok); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	// tamper -> must fail
	tok.Subject = "evil"
	if err := Verify(tok); err == nil {
		t.Fatal("Verify accepted a tampered token")
	}
}

func TestRequireApprovalRefused(t *testing.T) {
	_, err := RequireApproval(context.Background(),
		Request{Action: "launch", Subject: "x", Methods: []Method{mMock}},
		WithApprover(mockApprover{err: ErrRefused}),
	)
	if err != ErrRefused {
		t.Fatalf("want ErrRefused, got %v", err)
	}
}

func TestNoMethod(t *testing.T) {
	_, err := RequireApproval(context.Background(),
		Request{Action: "launch", Subject: "x", Methods: []Method{"nope"}},
		WithApprover(mockApprover{}),
	)
	if err != ErrNoMethod {
		t.Fatalf("want ErrNoMethod, got %v", err)
	}
}

func TestTokenRoundTripJSON(t *testing.T) {
	tok, err := RequireApproval(context.Background(),
		Request{Action: "write", Subject: "/etc/hosts", Methods: []Method{mMock}},
		WithApprover(mockApprover{}),
	)
	if err != nil {
		t.Fatal(err)
	}
	b, err := tok.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseToken(b)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(got); err != nil {
		t.Fatalf("Verify after round-trip: %v", err)
	}
}

func TestExecApproverExitCodes(t *testing.T) {
	// exit 0 approves
	if _, err := RequireApproval(context.Background(),
		Request{Action: "launch", Subject: "x", Methods: []Method{MethodRoute}},
		WithApprover(NewExecApprover(MethodRoute, "true")),
	); err != nil {
		t.Fatalf("exit-0 should approve, got %v", err)
	}
	// non-zero refuses
	if _, err := RequireApproval(context.Background(),
		Request{Action: "launch", Subject: "x", Methods: []Method{MethodRoute}},
		WithApprover(NewExecApprover(MethodRoute, "false")),
	); err != ErrRefused {
		t.Fatalf("exit-1 should refuse, got %v", err)
	}
}
