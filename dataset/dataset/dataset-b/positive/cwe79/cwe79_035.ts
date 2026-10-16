function renderUserComment(comment: string): string {
  return `<div class="comment">${comment}</div>`;
}

// Usage example:
const userInput = "<script>alert('XSS')</script>";
const html = renderUserComment(userInput);
document.getElementById('app').innerHTML = html;