function renderUserComment(comment) {
  const div = document.createElement('div');
  div.innerHTML = comment;
  document.body.appendChild(div);
}

const userInput = document.getElementById('userInput').value;
renderUserComment(userInput);