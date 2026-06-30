package contracts

import "google.golang.org/protobuf/types/known/wrapperspb"

// The M1 scaffold keeps protobuf wrapper messages so it builds before protoc
// generation is configured. The wrapper value carries a small JSON envelope for
// the first real step; generated contract types are planned next.
type SignalFingerprintConfig = wrapperspb.StringValue
type SignalFingerprintInput = wrapperspb.StringValue
type SignalFingerprintOutput = wrapperspb.StringValue
