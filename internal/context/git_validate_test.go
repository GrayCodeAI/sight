package context

import (
	"strings"
	"testing"
)

func TestValidateGitRef_ValidRefs(t *testing.T) {
	t.Parallel()
	valid := []string{
		"main",
		"feature/my-branch",
		"v1.2.3",
		"release/2026.01",
		"abc123def456", // hex SHA
		"HEAD",
		"HEAD~1",
		"my_branch",
		"fix-123",
	}
	for _, ref := range valid {
		if err := ValidateGitRef(ref); err != nil {
			t.Errorf("ValidateGitRef(%q) = %v, want nil", ref, err)
		}
	}
}

func TestValidateGitRef_RejectsInvalid(t *testing.T) {
	t.Parallel()
	cases := []struct {
		ref  string
		want string
	}{
		{"", "empty git ref"},
		{"-force", "starts with dash"},
		{"main;rm -rf", "forbidden characters"},
		{"feat|cat /etc/passwd", "forbidden characters"},
		{"branch$(cmd)", "forbidden characters"},
		{"name with space", "forbidden characters"},
		{"back\\slash", "forbidden characters"},
		{"new\nline", "forbidden characters"},
		{"wild*card", "forbidden characters"},
		{"ques?tion", "forbidden characters"},
	}
	for _, tc := range cases {
		err := ValidateGitRef(tc.ref)
		if err == nil {
			t.Errorf("ValidateGitRef(%q) = nil, want error containing %q", tc.ref, tc.want)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("ValidateGitRef(%q) error = %q, want containing %q", tc.ref, err.Error(), tc.want)
		}
	}
}
