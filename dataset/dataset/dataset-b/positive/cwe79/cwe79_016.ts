function renderUserComment(comment: string) {
  const div = document.createElement('div');
  div.innerHTML = `<p>${comment}</p>`;
  document.body.appendChild(div);
}