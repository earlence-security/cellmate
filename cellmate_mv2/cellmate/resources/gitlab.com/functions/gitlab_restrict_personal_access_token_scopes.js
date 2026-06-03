export default function restrictPersonalAccessTokenScopes(params, input) {
    const { selectedScopes } = input;
    const { allowedScopes } = params;
    // Check types
    if (!Array.isArray(selectedScopes) || !Array.isArray(allowedScopes)) {
        return false;
    }
    return selectedScopes.every(scope => allowedScopes.includes(scope));
}