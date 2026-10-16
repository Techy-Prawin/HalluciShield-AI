function renderUserComment(comment: string): string {
  return `<div class="comment">${comment}</div>`;
}

const userInput = "<script>alert('XSS')</script>";
const output = renderUserComment(userInput);
document.body.innerHTML = output;