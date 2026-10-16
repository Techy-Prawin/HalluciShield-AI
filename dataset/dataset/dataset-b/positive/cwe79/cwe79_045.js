function renderComment(comment) {
  const div = document.createElement('div');
  div.innerHTML = comment;
  document.body.appendChild(div);
}