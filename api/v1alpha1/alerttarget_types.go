package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// Alert target types.
const (
	AlertTypeSlack   = "slack"
	AlertTypeDiscord = "discord"
	AlertTypeTeams   = "teams"
	AlertTypeWebhook = "webhook"
)

// AlertTargetSpec defines where and when alerts are delivered.
type AlertTargetSpec struct {
	// Type is the kind of destination.
	// +kubebuilder:validation:Enum=slack;discord;teams;webhook
	Type string `json:"type"`
	// SecretRef references the Secret holding the destination URL.
	SecretRef SecretReference `json:"secretRef"`
	// Immediate configures immediate alerts.
	// +kubebuilder:default={}
	Immediate ImmediateSpec `json:"immediate,omitempty"`
	// Digest configures the scheduled digest.
	// +kubebuilder:default={}
	Digest DigestSpec `json:"digest,omitempty"`
	// Namespaces limits alerts to these namespaces.
	// +listType=atomic
	Namespaces []string `json:"namespaces,omitempty"`
	// NamespaceSelector limits alerts to namespaces matching these labels.
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector,omitempty"`
	// QuietHours suppresses alerts during the given intervals.
	QuietHours *QuietHours `json:"quietHours,omitempty"`
	// NotifyOnFeedStale sends an alert when vulnerability data goes stale.
	// +kubebuilder:default=false
	NotifyOnFeedStale bool `json:"notifyOnFeedStale,omitempty"`
	// Paused stops all deliveries to this target.
	// +kubebuilder:default=false
	Paused bool `json:"paused,omitempty"`
	// AllowPrivate permits delivery to private network addresses.
	// +kubebuilder:default=false
	AllowPrivate bool `json:"allowPrivate,omitempty"`
}

// SecretReference references a Secret in the ffs namespace.
type SecretReference struct {
	// Name is the Secret name in the ffs namespace.
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
	// URLKey is the Secret key holding the destination URL.
	// +kubebuilder:default="url"
	URLKey string `json:"urlKey,omitempty"`
	// SigningSecretKey is the Secret key holding the signing secret (webhook only).
	// +kubebuilder:default="signingSecret"
	SigningSecretKey string `json:"signingSecretKey,omitempty"`
}

// ImmediateSpec configures immediate alerts.
type ImmediateSpec struct {
	// MinPriority is the lowest priority that triggers an immediate alert.
	// +kubebuilder:default=urgent
	// +kubebuilder:validation:Enum=urgent;high;medium;low
	MinPriority string `json:"minPriority,omitempty"`
}

// DigestSpec configures the scheduled digest.
type DigestSpec struct {
	// Schedule is a cron expression.
	// +kubebuilder:default="0 9 * * *"
	Schedule string `json:"schedule,omitempty"`
	// TimeZone is the IANA time zone the schedule runs in.
	// +kubebuilder:default="UTC"
	TimeZone string `json:"timeZone,omitempty"`
	// MinPriority is the lowest priority included in the digest.
	// +kubebuilder:default=medium
	// +kubebuilder:validation:Enum=urgent;high;medium;low
	MinPriority string `json:"minPriority,omitempty"`
	// IncludeResolved includes recently resolved findings in the digest.
	// +kubebuilder:default=true
	IncludeResolved *bool `json:"includeResolved,omitempty"`
}

// QuietHours defines when alerts are suppressed.
type QuietHours struct {
	// Intervals lists the quiet intervals.
	// +kubebuilder:validation:MinItems=1
	// +listType=atomic
	Intervals []TimeInterval `json:"intervals"`
	// AllowUrgent lets urgent alerts through during quiet hours.
	// +kubebuilder:default=true
	AllowUrgent *bool `json:"allowUrgent,omitempty"`
}

// TimeInterval follows Alertmanager time_interval semantics: weekdays such as
// "monday:friday", daysOfMonth such as "1:5" or "-1", months such as
// "january:march" or "1:3", and years such as "2026:2027".
type TimeInterval struct {
	// Times lists times of day.
	// +listType=atomic
	Times []TimeRange `json:"times,omitempty"`
	// Weekdays lists weekdays or weekday ranges.
	// +listType=atomic
	Weekdays []string `json:"weekdays,omitempty"`
	// DaysOfMonth lists days of the month or ranges.
	// +listType=atomic
	DaysOfMonth []string `json:"daysOfMonth,omitempty"`
	// Months lists months or month ranges.
	// +listType=atomic
	Months []string `json:"months,omitempty"`
	// Years lists years or year ranges.
	// +listType=atomic
	Years []string `json:"years,omitempty"`
	// Location is the IANA time zone for the interval.
	// +kubebuilder:default="UTC"
	Location string `json:"location,omitempty"`
}

// TimeRange is a range of times within a day, as HH:MM.
type TimeRange struct {
	// StartTime is the start of the range.
	// +kubebuilder:validation:Pattern=`^(([01][0-9]|2[0-3]):[0-5][0-9]|24:00)$`
	StartTime string `json:"startTime"`
	// EndTime is the end of the range.
	// +kubebuilder:validation:Pattern=`^(([01][0-9]|2[0-3]):[0-5][0-9]|24:00)$`
	EndTime string `json:"endTime"`
}

// AlertTargetStatus is the observed state of an alert target.
type AlertTargetStatus struct {
	// LastDelivery is when an alert was last delivered.
	LastDelivery *metav1.Time `json:"lastDelivery,omitempty"`
	// LastError is the most recent delivery error.
	LastError string `json:"lastError,omitempty"`
	// ObservedGeneration is the last generation processed.
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// Conditions describe the target state.
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// AlertTarget is a destination for alerts.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories=ffs
// +kubebuilder:printcolumn:name="Type",type=string,JSONPath=`.spec.type`
// +kubebuilder:printcolumn:name="Paused",type=boolean,JSONPath=`.spec.paused`
// +kubebuilder:printcolumn:name="Last Delivery",type=date,JSONPath=`.status.lastDelivery`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type AlertTarget struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AlertTargetSpec   `json:"spec"`
	Status AlertTargetStatus `json:"status,omitempty"`
}

// AlertTargetList is a list of alert targets.
//
// +kubebuilder:object:root=true
type AlertTargetList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AlertTarget `json:"items"`
}

func init() { SchemeBuilder.Register(&AlertTarget{}, &AlertTargetList{}) }
