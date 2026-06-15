function e(t){switch(t){case"create":return"POST";case"edit":return"PUT";default:throw new Error("Unknown policy action: ".concat(t))}}export{e as methodForPolicyAction};
