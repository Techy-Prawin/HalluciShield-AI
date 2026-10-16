function renderUserComment(comment) {
    const div = document.createElement('div');
    div.innerHTML = '<p>' + comment + '</p>';
    document.body.appendChild(div);
}

// Example usage with untrusted input
const userInput = '<script>alert("XSS")</script>';
renderUserComment(userInput);