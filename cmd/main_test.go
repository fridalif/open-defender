package main

import (
	"errors"
	"testing"

	"open-defender/pkg/app"
	"open-defender/pkg/app/mocks"

	"go.uber.org/mock/gomock"
)

func factory(a app.App) func() app.App {
	return func() app.App { return a }
}

func TestRunUnknownArg(t *testing.T) {
	if code := run([]string{"open-defender", "--nope"}, factory(nil), true); code != 1 {
		t.Fatalf("run() = %d, want 1", code)
	}
}

func TestRunHelp(t *testing.T) {
	if code := run([]string{"open-defender", "-h"}, factory(nil), true); code != 0 {
		t.Fatalf("run() = %d, want 0", code)
	}
}

func TestRunTest(t *testing.T) {
	ctrl := gomock.NewController(t)
	a := mocks.NewMockApp(ctrl)
	a.EXPECT().TestConfig().Return(nil)

	if code := run([]string{"open-defender", "-t"}, factory(a), false); code != 0 {
		t.Fatalf("run() = %d, want 0", code)
	}
}

func TestRunTestFailure(t *testing.T) {
	ctrl := gomock.NewController(t)
	a := mocks.NewMockApp(ctrl)
	a.EXPECT().TestConfig().Return(errors.New("invalid"))

	if code := run([]string{"open-defender", "-t"}, factory(a), false); code != 1 {
		t.Fatalf("run() = %d, want 1", code)
	}
}

func TestRunStatus(t *testing.T) {
	ctrl := gomock.NewController(t)
	a := mocks.NewMockApp(ctrl)
	a.EXPECT().Status().Return(nil)

	if code := run([]string{"open-defender", "-s"}, factory(a), false); code != 0 {
		t.Fatalf("run() = %d, want 0", code)
	}
}

func TestRunStatusFailure(t *testing.T) {
	ctrl := gomock.NewController(t)
	a := mocks.NewMockApp(ctrl)
	a.EXPECT().Status().Return(errors.New("boom"))

	if code := run([]string{"open-defender", "-s"}, factory(a), true); code != 1 {
		t.Fatalf("run() = %d, want 1", code)
	}
}

func TestRunNotRoot(t *testing.T) {
	ctrl := gomock.NewController(t)
	a := mocks.NewMockApp(ctrl)

	if code := run([]string{"open-defender", "-u"}, factory(a), false); code != 1 {
		t.Fatalf("run() = %d, want 1 for a non-root privileged action", code)
	}
}

func TestRunUpdate(t *testing.T) {
	ctrl := gomock.NewController(t)
	a := mocks.NewMockApp(ctrl)
	a.EXPECT().Update().Return(nil)

	if code := run([]string{"open-defender", "-u"}, factory(a), true); code != 0 {
		t.Fatalf("run() = %d, want 0", code)
	}
}

func TestRunUpdateFailure(t *testing.T) {
	ctrl := gomock.NewController(t)
	a := mocks.NewMockApp(ctrl)
	a.EXPECT().Update().Return(errors.New("boom"))

	if code := run([]string{"open-defender", "-u"}, factory(a), true); code != 1 {
		t.Fatalf("run() = %d, want 1", code)
	}
}

func TestRunRestart(t *testing.T) {
	ctrl := gomock.NewController(t)
	a := mocks.NewMockApp(ctrl)
	a.EXPECT().Restart().Return(nil)

	if code := run([]string{"open-defender", "-r"}, factory(a), true); code != 0 {
		t.Fatalf("run() = %d, want 0", code)
	}
}

func TestRunRestartFailure(t *testing.T) {
	ctrl := gomock.NewController(t)
	a := mocks.NewMockApp(ctrl)
	a.EXPECT().Restart().Return(errors.New("boom"))

	if code := run([]string{"open-defender", "-r"}, factory(a), true); code != 1 {
		t.Fatalf("run() = %d, want 1", code)
	}
}

func TestRunInstall(t *testing.T) {
	ctrl := gomock.NewController(t)
	a := mocks.NewMockApp(ctrl)
	a.EXPECT().Initialize().Return(nil)
	a.EXPECT().Install().Return(nil)

	if code := run([]string{"open-defender", "-i"}, factory(a), true); code != 0 {
		t.Fatalf("run() = %d, want 0", code)
	}
}

func TestRunInstallInitializeFailure(t *testing.T) {
	ctrl := gomock.NewController(t)
	a := mocks.NewMockApp(ctrl)
	a.EXPECT().Initialize().Return(errors.New("boom"))

	if code := run([]string{"open-defender", "-i"}, factory(a), true); code != 1 {
		t.Fatalf("run() = %d, want 1", code)
	}
}

func TestRunInstallFailure(t *testing.T) {
	ctrl := gomock.NewController(t)
	a := mocks.NewMockApp(ctrl)
	a.EXPECT().Initialize().Return(nil)
	a.EXPECT().Install().Return(errors.New("boom"))

	if code := run([]string{"open-defender", "-i"}, factory(a), true); code != 1 {
		t.Fatalf("run() = %d, want 1", code)
	}
}

func TestRunDefaultRuns(t *testing.T) {
	ctrl := gomock.NewController(t)
	a := mocks.NewMockApp(ctrl)
	a.EXPECT().Initialize().Return(nil)
	a.EXPECT().Run()

	if code := run([]string{"open-defender"}, factory(a), true); code != 0 {
		t.Fatalf("run() = %d, want 0", code)
	}
}
