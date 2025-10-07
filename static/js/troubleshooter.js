// troubleshooter.ts
function checkPolicy() {
    var data = {};
    document.querySelectorAll(".form-control").forEach(function(input) {
        data[input.id] = input.value;
    });
    fetch("/admin/api/policy_troubleshooter", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(data)
    }).then(function(response) {
        return response.json();
    }).then(function(result) {
        console.log("Policy check result:", result);
        var resultsDiv = document.getElementById("results");
        if (!resultsDiv) return;
        // Clear previous results
        while(resultsDiv.firstChild){
            resultsDiv.removeChild(resultsDiv.firstChild);
        }
        // Create and append decision heading
        var decisionHeading = document.createElement("h3");
        decisionHeading.innerHTML = 'Decision: <span class="badge badge-'.concat(result.decision.toLowerCase(), '">').concat(result.decision, "</span>");
        resultsDiv.appendChild(decisionHeading);
        // Create and append reason paragraph
        var reasonParagraph = document.createElement("p");
        reasonParagraph.textContent = "Reason: ".concat(result.reason);
        resultsDiv.appendChild(reasonParagraph);
        // Create and append deny policies heading
        var denyPoliciesHeading = document.createElement("h4");
        denyPoliciesHeading.textContent = "Deny Policies:";
        resultsDiv.appendChild(denyPoliciesHeading);
        // Create and append deny policies list
        var denyPoliciesList = document.createElement("ul");
        result.deny_policies.forEach(function(policy) {
            var listItem = document.createElement("li");
            listItem.textContent = policy;
            denyPoliciesList.appendChild(listItem);
        });
        resultsDiv.appendChild(denyPoliciesList);
        // Create and append allow policies heading
        var allowPoliciesHeading = document.createElement("h4");
        allowPoliciesHeading.textContent = "Allow Policies:";
        resultsDiv.appendChild(allowPoliciesHeading);
        // Create and append allow policies list
        var allowPoliciesList = document.createElement("ul");
        result.allow_policies.forEach(function(policy) {
            var listItem = document.createElement("li");
            listItem.textContent = policy;
            allowPoliciesList.appendChild(listItem);
        });
        resultsDiv.appendChild(allowPoliciesList);
        // Create and append not applicable policies heading
        var notApplicablePoliciesHeading = document.createElement("h4");
        notApplicablePoliciesHeading.textContent = "Not Applicable Policies:";
        resultsDiv.appendChild(notApplicablePoliciesHeading);
        // Create and append not applicable policies list
        var notApplicablePoliciesList = document.createElement("ul");
        result.not_applicable_policies.forEach(function(policy) {
            var listItem = document.createElement("li");
            listItem.textContent = policy;
            notApplicablePoliciesList.appendChild(listItem);
        });
        resultsDiv.appendChild(notApplicablePoliciesList);
    }).catch(function(error) {
        console.error("Error checking policy:", error);
        var resultsDiv = document.getElementById("results");
        if (!resultsDiv) return;
        // Clear previous results
        while(resultsDiv.firstChild){
            resultsDiv.removeChild(resultsDiv.firstChild);
        }
        var errorContainer = document.createElement("div");
        errorContainer.className = "error-container";
        var errorHeading = document.createElement("h1");
        errorHeading.textContent = "Error checking policy. Please try again.";
        errorContainer.appendChild(errorHeading);
        var errorMessage = document.createElement("p");
        errorMessage.textContent = error.toString();
        errorContainer.appendChild(errorMessage);
        resultsDiv.appendChild(errorContainer);
    });
}
var debounce_timer = 0;
function debouncedCheck(debounce_timer) {
    if (!debounce_timer) {
        debounce_timer = window.setTimeout(function() {
            debounce_timer = 0; // Reset the timer after execution
            checkPolicy();
        }, 300);
    } else {
        console.debug("Debounce timer is still running. Waiting for it to expire.");
    }
}
document.querySelectorAll(" .form-control").forEach(function(input) {
    input.addEventListener("input", function() {
        console.debug("Input changed: ".concat(input.id, " = ").concat(input.value));
        // update the URL parameters
        var url = new URL(window.location.href);
        url.searchParams.set(input.id, input.value);
        console.debug("Updated URL: ".concat(url.toString()));
        window.history.pushState({}, '', url);
        debouncedCheck(debounce_timer);
    });
});
document.getElementsByName("check_access").forEach(function(input) {
    input.addEventListener("click", function(event) {
        event.preventDefault();
        debouncedCheck(debounce_timer);
    });
    input.addEventListener("submit", function(event) {
        event.preventDefault();
        debouncedCheck(debounce_timer);
    });
});
// On page load, populate the form fields from URL parameters
window.addEventListener("load", function() {
    var has_something = false;
    document.querySelectorAll(".form-control").forEach(function(input) {
        if (input.value) {
            has_something = true;
        }
    });
    if (has_something) {
        debouncedCheck(debounce_timer);
    }
});
