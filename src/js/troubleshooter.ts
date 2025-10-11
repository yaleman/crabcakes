// troubleshooter.ts

import { context } from "esbuild";
import { ErrorMessage } from "./shared";

interface PolicyCheckData {
    [key: string]: string;
}


interface PolicyCheckResult {
    decision: {
        decision: string;
        matched_statements: {
            sid: string;
            effect: string;
            conditions_satisfied: boolean;
            reason: string;
        }[];
        context: {
            Principal: Record<string, string>;
            Action: string;
            Resource: string;
            Context: Record<string, string>;
        };
    };
}

function checkPolicy(): void {
    const data: PolicyCheckData = {};
    document.querySelectorAll<HTMLInputElement>(".form-control").forEach((input) => {
        if (input.value.length > 0) {
            data[input.id] = input.value;
        } else {
            data[input.id] = "";
        }
    });

    fetch("/admin/api/policy_troubleshooter", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(data)
    })
        .then(response => response.json())
        .then((result: PolicyCheckResult | ErrorMessage) => {
            if ('decision' in result && typeof result.decision === 'object') {

                console.log("Policy check result:", result);
                const resultsDiv = document.getElementById("results");
                if (!resultsDiv) return;

                // Clear previous results
                while (resultsDiv.firstChild) {
                    resultsDiv.removeChild(resultsDiv.firstChild);
                }

                // Create and append decision heading
                const decisionHeading = document.createElement("h3");
                decisionHeading.innerHTML = `Decision: <span class="badge badge-${result.decision.decision.toLowerCase()}">${result.decision.decision}</span>`;
                resultsDiv.appendChild(decisionHeading);

                // Create and append context heading
                const contextHeading = document.createElement("h3");
                contextHeading.textContent = "Context:";
                resultsDiv.appendChild(contextHeading);


                const contextParagraph = document.createElement("p");

                const principal = document.createElement("div");

                const principalLabel = document.createElement("label");
                principalLabel.htmlFor = "principal";
                principalLabel.innerText = "Principal: ";
                principal.appendChild(principalLabel);

                const principalValue = document.createElement("span");
                principalValue.id = "principal";
                var arn: string;
                if (Object.entries(result.decision.context.Principal).length === 0) {
                    arn = "No principal specified";
                } else {
                    // hacky workaround for the mock account ID thing
                    arn = Object.entries(result.decision.context.Principal).map(([_, value]) => value.replace("::000000000000:", ":::")).join(", ");
                }

                principalValue.innerText = arn;
                principal.appendChild(principalValue);
                contextParagraph.appendChild(principal);

                const actionParagraph = document.createElement("p");
                const action = document.createElement("div");
                const actionLabel = document.createElement("label");
                actionLabel.htmlFor = "action";
                actionLabel.innerText = "Action: ";
                action.appendChild(actionLabel);

                const actionValue = document.createElement("span");
                actionValue.id = "action";
                actionValue.innerText = result.decision.context.Action;
                action.appendChild(actionValue);
                actionParagraph.appendChild(action);
                contextParagraph.appendChild(actionParagraph);

                const resourceParagraph = document.createElement("p");
                const resource = document.createElement("div");

                const resourceLabel = document.createElement("label");
                resourceLabel.htmlFor = "resource";
                resourceLabel.innerText = "Resource: ";
                resource.appendChild(resourceLabel);

                const resourceValue = document.createElement("span");
                resourceValue.id = "resource";
                resourceValue.innerText = result.decision.context.Resource;
                resource.appendChild(resourceValue);
                resourceParagraph.appendChild(resource);
                contextParagraph.appendChild(resourceParagraph);

                if (result.decision.context.Context && Object.keys(result.decision.context.Context).length > 0) {
                    const contextJSONParagraph = document.createElement("p");
                    const contextJSON = document.createElement("div");
                    contextJSON.innerText = `Context: ${JSON.stringify(result.decision.context.Context, null, 2)} `;
                    contextJSONParagraph.appendChild(contextJSON);
                    contextParagraph.appendChild(contextJSONParagraph);
                }

                resultsDiv.appendChild(contextParagraph);

                const matched_statements = document.createElement("h3");
                matched_statements.textContent = "Matched Statements";
                resultsDiv.appendChild(matched_statements);

                // Create and append matched statements list
                const matchedStatementsParagraph = document.createElement("div");

                const matchedStatementsList = document.createElement("ul");
                matchedStatementsList.classList = ["no-list-style ", "list-item-padded"].join(" ");

                result.decision.matched_statements.forEach(statement => {
                    const listItem = document.createElement("li");

                    const subList = document.createElement("ul");
                    subList.classList = ["no-list-style"].join(" ");
                    const statementHeading = document.createElement("li");
                    statementHeading.className = "font-weight-bold";
                    statementHeading.textContent = `Statement ID: ${statement.sid} `;
                    subList.appendChild(statementHeading);

                    const conditionsItem = document.createElement("li");
                    conditionsItem.innerHTML = `Conditions Satisfied: <span class="badge badge-${statement.conditions_satisfied.toString().toLowerCase()}" > ${statement.conditions_satisfied} </span>`;
                    subList.appendChild(conditionsItem);

                    if (statement.conditions_satisfied) {
                        const effectItem = document.createElement("li");
                        effectItem.innerHTML = `Policy Effect: <span class="badge badge-${statement.effect.toLowerCase()}">${statement.effect}</span>`;
                        subList.appendChild(effectItem);
                    }


                    if (statement.reason.trim() !== "" && statement.reason) {
                        const reasonItem = document.createElement("li");
                        reasonItem.innerText = `Reason: ${statement.reason}`;
                        subList.appendChild(reasonItem);

                    }

                    listItem.appendChild(subList);
                    matchedStatementsList.appendChild(listItem);
                });
                matchedStatementsParagraph.appendChild(matchedStatementsList);
                resultsDiv.appendChild(matchedStatementsParagraph);
            } else if ('error' in result) {
                showError(result as ErrorMessage);
            }
        })
        .catch(error => {
            showError(error)
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

function showError(error: ErrorMessage | string): void {
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
    if (typeof error === "string") {
        errorMessage.textContent = error;
    } else {

        errorMessage.textContent = JSON.stringify(error.error);
    }
    errorContainer.appendChild(errorMessage);
    resultsDiv.appendChild(errorContainer);
}

document.querySelectorAll<HTMLInputElement>(".form-control").forEach((input) => {
    input.addEventListener("input", () => {
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
