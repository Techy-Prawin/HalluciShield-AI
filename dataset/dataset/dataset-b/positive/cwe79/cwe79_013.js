function renderUserComment(comment) {
    const div = document.createElement('div');
    div.innerHTML = '<p>Comment: ' + comment + '</p>';
    document.body.appendChild(div);
}