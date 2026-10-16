function renderUserComment(comment) {
    const container = document.getElementById('comment-box');
    container.innerHTML = '<div class="comment">' + comment + '</div>';
}