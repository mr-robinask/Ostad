document.getElementById('contact-form').addEventListener('submit', function(e) {
    e.preventDefault();

    const name = document.getElementById('name').value.trim();
    const email = document.getElementById('email').value.trim();
    const message = document.getElementById('message').value.trim();
    const formMessage = document.getElementById('form-message');

    // Email validation regex
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    if (!name || !email || !message) {
        formMessage.style.display = 'block';
        formMessage.classList.remove('success');
        formMessage.classList.add('error');
        formMessage.textContent = 'All fields are required!';
        return;
    }

    if (!emailRegex.test(email)) {
        formMessage.style.display = 'block';
        formMessage.classList.remove('success');
        formMessage.classList.add('error');
        formMessage.textContent = 'Please enter a valid email address!';
        return;
    }

    // Save to localStorage
    const submission = { name, email, message, timestamp: new Date().toISOString() };
    let submissions = JSON.parse(localStorage.getItem('formSubmissions')) || [];
    submissions.push(submission);
    localStorage.setItem('formSubmissions', JSON.stringify(submissions));

    // Show success message
    formMessage.style.display = 'block';
    formMessage.classList.remove('error');
    formMessage.classList.add('success');
    formMessage.textContent = 'Form submitted successfully!';

    // Reset form
    this.reset();

    // Display saved submissions
    displaySubmissions();
});

function displaySubmissions() {
    const submissionList = document.getElementById('submission-list');
    const savedDataDiv = document.getElementById('saved-data');
    const submissions = JSON.parse(localStorage.getItem('formSubmissions')) || [];

    if (submissions.length > 0) {
        savedDataDiv.style.display = 'block';
        submissionList.innerHTML = '';
        submissions.forEach(sub => {
            const li = document.createElement('li');
            li.textContent = `${sub.name} (${sub.email}): ${sub.message} - ${new Date(sub.timestamp).toLocaleString()}`;
            submissionList.appendChild(li);
        });
    }
}

// Load saved submissions on page load
window.onload = displaySubmissions;
