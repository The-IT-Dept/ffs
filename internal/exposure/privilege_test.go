package exposure

import (
	"slices"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/ptr"
)

func TestPrivilege(t *testing.T) {
	sc := func(s corev1.SecurityContext) corev1.Container {
		return corev1.Container{Name: "c", SecurityContext: &s}
	}
	spec := func(mod func(*corev1.PodSpec)) *corev1.PodSpec {
		s := &corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}}
		mod(s)
		return s
	}
	caps := func(c ...corev1.Capability) corev1.SecurityContext {
		return corev1.SecurityContext{Capabilities: &corev1.Capabilities{Add: c}}
	}
	cases := []struct {
		name string
		spec *corev1.PodSpec
		want []string
	}{
		{"privileged", spec(func(s *corev1.PodSpec) { s.Containers[0] = sc(corev1.SecurityContext{Privileged: ptr.To(true)}) }), []string{"privileged container"}},
		{"privileged false", spec(func(s *corev1.PodSpec) { s.Containers[0] = sc(corev1.SecurityContext{Privileged: ptr.To(false)}) }), nil},
		{"pod runAsUser 0", spec(func(s *corev1.PodSpec) { s.SecurityContext = &corev1.PodSecurityContext{RunAsUser: ptr.To(int64(0))} }), []string{"runs as root"}},
		{"container runAsUser 0", spec(func(s *corev1.PodSpec) { s.Containers[0] = sc(corev1.SecurityContext{RunAsUser: ptr.To(int64(0))}) }), []string{"runs as root"}},
		{"container runAsUser 0 + runAsNonRoot", spec(func(s *corev1.PodSpec) {
			s.Containers[0] = sc(corev1.SecurityContext{RunAsUser: ptr.To(int64(0)), RunAsNonRoot: ptr.To(true)})
		}), nil},
		{"container user overrides pod root", spec(func(s *corev1.PodSpec) {
			s.SecurityContext = &corev1.PodSecurityContext{RunAsUser: ptr.To(int64(0))}
			s.Containers[0] = sc(corev1.SecurityContext{RunAsUser: ptr.To(int64(1000))})
		}), nil},
		{"pod runAsNonRoot inherited", spec(func(s *corev1.PodSpec) {
			s.SecurityContext = &corev1.PodSecurityContext{RunAsUser: ptr.To(int64(0)), RunAsNonRoot: ptr.To(true)}
		}), nil},
		{"no runAsUser", spec(func(*corev1.PodSpec) {}), nil},
		{"hostPID hostIPC", spec(func(s *corev1.PodSpec) { s.HostPID, s.HostIPC = true, true }), []string{"host IPC namespace", "host PID namespace"}},
		{"hostPath", spec(func(s *corev1.PodSpec) {
			s.Volumes = []corev1.Volume{{Name: "d", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/docker.sock"}}}}
		}), []string{"hostPath volume /var/run/docker.sock"}},
		{"capabilities", spec(func(s *corev1.PodSpec) {
			s.Containers[0] = sc(caps("NET_ADMIN", "CAP_SYS_ADMIN", "NET_BIND_SERVICE", "chown"))
		}), []string{"added capabilities NET_ADMIN, SYS_ADMIN"}},
		{"capability ALL", spec(func(s *corev1.PodSpec) { s.Containers[0] = sc(caps("ALL")) }), []string{"added capabilities ALL"}},
		{"init container", spec(func(s *corev1.PodSpec) {
			s.InitContainers = []corev1.Container{sc(corev1.SecurityContext{Privileged: ptr.To(true)})}
		}), []string{"privileged container"}},
		{"ephemeral container", spec(func(s *corev1.PodSpec) {
			s.EphemeralContainers = []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "dbg",
				SecurityContext: &corev1.SecurityContext{Privileged: ptr.To(true)}}}}
		}), []string{"privileged container"}},
		{"capabilities merge across containers", spec(func(s *corev1.PodSpec) {
			s.Containers = []corev1.Container{sc(caps("SYS_ADMIN")), sc(caps("NET_ADMIN"))}
		}), []string{"added capabilities NET_ADMIN, SYS_ADMIN"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := privilegeReasons([]*corev1.PodSpec{tc.spec})
			if !slices.Equal(got, tc.want) {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
