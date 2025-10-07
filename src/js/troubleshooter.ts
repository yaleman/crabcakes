// troubleshooter.ts

interface PolicyCheckData {
    [key: string]: string;
}


interface PolicyCheckResult {
    decision: string;
    reason: string;
    deny_policies: string[];
    allow_policies: string[];
    not_applicable_policies: string[];
}

function checkPolicy(): void {
    const data: PolicyCheckData = {};
    document.querySelectorAll<HTMLInputElement>(".form-control").forEach((input) => {
        data[input.id] = input.value;
    });

    fetch("/admin/api/policy_troubleshooter", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(data)
    })
        .then(response => response.json())
        .then((result: PolicyCheckResult) => {
            console.log("Policy check result:", result);
            const resultsDiv = document.getElementById("results");
            if (!resultsDiv) return;

            // Clear previous results
            while (resultsDiv.firstChild) {
                resultsDiv.removeChild(resultsDiv.firstChild);
            }

            // Create and append decision heading
            const decisionHeading = document.createElement("h3");
            decisionHeading.innerHTML = `Decision: <span class="badge badge-${result.decision.toLowerCase()}">${result.decision}</span>`;
            resultsDiv.appendChild(decisionHeading);

            // Create and append reason paragraph
            const reasonParagraph = document.createElement("p");
            reasonParagraph.textContent = `Reason: ${result.reason}`;
            resultsDiv.appendChild(reasonParagraph);

            // Create and append deny policies heading
            const denyPoliciesHeading = document.createElement("h4");
            denyPoliciesHeading.textContent = "Deny Policies:";
            resultsDiv.appendChild(denyPoliciesHeading);

            // Create and append deny policies list
            const denyPoliciesList = document.createElement("ul");
            result.deny_policies.forEach(policy => {
                const listItem = document.createElement("li");
                listItem.textContent = policy;
                denyPoliciesList.appendChild(listItem);
            });
            resultsDiv.appendChild(denyPoliciesList);


            // Create and append allow policies heading
            const allowPoliciesHeading = document.createElement("h4");
            allowPoliciesHeading.textContent = "Allow Policies:";
            resultsDiv.appendChild(allowPoliciesHeading);

            // Create and append allow policies list
            const allowPoliciesList = document.createElement("ul");
            result.allow_policies.forEach(policy => {
                const listItem = document.createElement("li");
                listItem.textContent = policy;
                allowPoliciesList.appendChild(listItem);
            });
            resultsDiv.appendChild(allowPoliciesList);

            // Create and append not applicable policies heading
            const notApplicablePoliciesHeading = document.createElement("h4");
            notApplicablePoliciesHeading.textContent = "Not Applicable Policies:";
            resultsDiv.appendChild(notApplicablePoliciesHeading);

            // Create and append not applicable policies list
            const notApplicablePoliciesList = document.createElement("ul");
            result.not_applicable_policies.forEach(policy => {
                const listItem = document.createElement("li");
                listItem.textContent = policy;
                notApplicablePoliciesList.appendChild(listItem);
            });
            resultsDiv.appendChild(notApplicablePoliciesList);
        })
        .catch(error => {
            console.error("Error checking policy:", error);
            const resultsDiv = document.getElementById("results");
            if (!resultsDiv) return;

            // Clear previous results
            while (resultsDiv.firstChild) {
                resultsDiv.removeChild(resultsDiv.firstChild);
            }
            const errorContainer = document.createElement("div");
            errorContainer.className = "error-container";

            const errorHeading = document.createElement("h1");
            errorHeading.textContent = "Error checking policy. Please try again.";
            errorContainer.appendChild(errorHeading);
            const errorMessage = document.createElement("p");
            errorMessage.textContent = error.toString();
            errorContainer.appendChild(errorMessage);
            resultsDiv.appendChild(errorContainer);



        });
}

let debounce_timer: number = 0;

function debouncedCheck(debounce_timer: number): void {
    if (!debounce_timer) {
        debounce_timer = window.setTimeout(() => {
            debounce_timer = 0; // Reset the timer after execution
            checkPolicy();
        }, 300);
    } else {
        console.debug("Debounce timer is still running. Waiting for it to expire.");
    }
}

document.querySelectorAll<HTMLInputElement>(".form-control").forEach((input) => {
    input.addEventListener("input", () => {
        console.debug(`Input changed: ${input.id} = ${input.value}`);
        // update the URL parameters
        const url = new URL(window.location.href);
        url.searchParams.set(input.id, input.value);
        console.debug(`Updated URL: ${url.toString()}`);
        window.history.pushState({}, '', url);
        debouncedCheck(debounce_timer);
    });

});
document.getElementsByName("check_access").forEach((input) => {
    input.addEventListener("click", (event: MouseEvent) => {
        event.preventDefault();
        debouncedCheck(debounce_timer);
    });
    input.addEventListener("submit", (event: Event) => {
        event.preventDefault();
        debouncedCheck(debounce_timer);
    });
});

// On page load, populate the form fields from URL parameters
window.addEventListener("load", () => {
    let has_something = false;
    document.querySelectorAll<HTMLInputElement>(".form-control").forEach((input) => {
        if (input.value) {
            has_something = true;
        }
    });
    if (has_something) { debouncedCheck(debounce_timer); }
});
