package permissions

// ResourceScoped permissions are ceilings, never boolean grants. A method may
// start under its policy ceiling, but every file operation needs exact resource
// authority from the Host-owned selected resource store.
func ResourceScoped(id string) bool { return id == "fs.selected.read" || id == "fs.selected.write" }

// MethodGrantIDs excludes resource ceilings only from method-start grant checks.
// Policy evaluation must continue to receive the complete declared ceiling.
func MethodGrantIDs(ids []string) []string {
	result := make([]string, 0, len(ids))
	for _, id := range NormalizePermissionIDs(ids) {
		if !ResourceScoped(id) {
			result = append(result, id)
		}
	}
	return result
}

func ResourceCeilingIDs(ids []string) []string {
	var result []string
	for _, id := range NormalizePermissionIDs(ids) {
		if ResourceScoped(id) {
			result = append(result, id)
		}
	}
	return result
}
