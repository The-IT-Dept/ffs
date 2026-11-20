package apiserver

import "time"

// stamp is what every response carries: the cluster name and the time it was generated.
func (s *Server) stamp() (cluster string, generatedAt time.Time) {
	return s.o.Config.ClusterName, s.o.Now().UTC()
}
