function renderUserComment(comment) {
    const container = document.getElementById('comments');
    container.innerHTML += '<div class="comment">' + comment + '</div>';
}