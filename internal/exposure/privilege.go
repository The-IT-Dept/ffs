package exposure

import (
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// defaultCaps is the capability set a container runtime grants by default.
var defaultCaps = map[string]bool{
	"AUDIT_WRITE": true, "CHOWN": true, "DAC_OVERRIDE": true, "FOWNER": true, "FSETID": true, "KILL": true,
	"MKNOD": true, "NET_BIND_SERVICE": true, "NET_RAW": true, "SETFCAP": true, "SETGID": true,
	"SETPCAP": true, "SETUID": true, "SYS_CHROOT": true,
}

// privilegeReasons returns the sorted, de-duplicated reasons the pod specs are privileged.
func privilegeReasons(specs []*corev1.PodSpec) []string {
	reasons := map[string]struct{}{}
	added := map[string]struct{}{}
	for _, spec := range specs {
		if spec.HostPID {
			reasons["host PID namespace"] = struct{}{}
		}
		if spec.HostIPC {
			reasons["host IPC namespace"] = struct{}{}
		}
		for _, v := range spec.Volumes {
			if v.HostPath != nil {
				reasons["hostPath volume "+v.HostPath.Path] = struct{}{}
			}
		}
		var scs []*corev1.SecurityContext
		for _, c := range spec.Containers {
			scs = append(scs, c.SecurityContext)
		}
		for _, c := range spec.InitContainers {
			scs = append(scs, c.SecurityContext)
		}
		for _, c := range spec.EphemeralContainers {
			scs = append(scs, c.SecurityContext)
		}
		for _, sc := range scs {
			if sc != nil && sc.Privileged != nil && *sc.Privileged {
				reasons["privileged container"] = struct{}{}
			}
			if sc != nil && sc.Capabilities != nil {
				for _, c := range sc.Capabilities.Add {
					n := strings.TrimPrefix(strings.ToUpper(string(c)), "CAP_")
					if n != "" && !defaultCaps[n] {
						added[n] = struct{}{}
					}
				}
			}
			if runsAsRoot(spec.SecurityContext, sc) {
				reasons["runs as root"] = struct{}{}
			}
		}
	}
	if len(added) > 0 {
		names := make([]string, 0, len(added))
		for n := range added {
			names = append(names, n)
		}
		sort.Strings(names)
		reasons[fmt.Sprintf("added capabilities %s", strings.Join(names, ", "))] = struct{}{}
	}
	if len(reasons) == 0 {
		return nil
	}
	out := make([]string, 0, len(reasons))
	for r := range reasons {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

// runsAsRoot reports whether the effective runAsUser is 0 and runAsNonRoot is not true. Each is
// the container's value, falling back to the pod's. An unset runAsUser is not root here: the image
// user decides, and inventory records that case on the container.
func runsAsRoot(pod *corev1.PodSecurityContext, c *corev1.SecurityContext) bool {
	var user *int64
	var nonRoot *bool
	if pod != nil {
		user, nonRoot = pod.RunAsUser, pod.RunAsNonRoot
	}
	if c != nil {
		if c.RunAsUser != nil {
			user = c.RunAsUser
		}
		if c.RunAsNonRoot != nil {
			nonRoot = c.RunAsNonRoot
		}
	}
	return user != nil && *user == 0 && (nonRoot == nil || !*nonRoot)
}
