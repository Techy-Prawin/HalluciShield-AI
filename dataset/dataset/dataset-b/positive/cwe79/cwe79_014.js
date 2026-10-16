function renderUserComment(comment) {
    const div = document.createElement('div');
    div.innerHTML = '<p>' + comment + '</p>';
    return div;
}