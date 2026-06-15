export function methodForPolicyAction(policyAction: string): 'POST' | 'PUT' {
    switch (policyAction) {
        case 'create':
            return 'POST';
        case 'edit':
            return 'PUT';
        default:
            throw new Error(`Unknown policy action: ${policyAction}`);
    }
}
