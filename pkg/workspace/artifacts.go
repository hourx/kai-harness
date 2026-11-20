package workspace

// ArtifactNames are the recon artifacts kai reports line counts for. They are
// part of the workspace contract: the CLI, the handoff pack and the service face
// all count the same files, so a number read from one matches the others.
//
// The slice is read-only. Callers iterate it; nobody appends to it.
var ArtifactNames = []string{
	"subs.txt",
	"live.txt",
	"urls.txt",
	"js.ts",
	"endpoints.txt",
	"nuclei.txt",
	"ranked.txt",
	"smuggling.txt",
}
