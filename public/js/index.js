const displayErrorMessage = (message) => {
    const errorMessageElement = document.getElementById('errorMessage');
    errorMessageElement.textContent = message;
    errorMessageElement.style.display = 'block';
};
//Registeration form
    document.getElementById('registrationForm').addEventListener('submit', async (event) => {
        event.preventDefault();

        const username = document.getElementById('username').value;
        const email = document.getElementById('email').value;
        const password = document.getElementById('password').value;

        const response = await fetch('/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, email, password })
        });

        if (response.ok) {
            document.getElementById('successMessage').innerText = 'User registered successfully.';
            document.getElementById('successMessage').style.display = 'block';
            document.getElementById('errorMessage').style.display = 'none';
        } else {
            const errorMessage = await response.text();
            document.getElementById('errorMessage').innerText = errorMessage;
            document.getElementById('errorMessage').style.display = 'block';
            document.getElementById('successMessage').style.display = 'none';
        }
        
    });
//Login form
document.getElementById('loginForm').addEventListener('submit', async (event) => {
    event.preventDefault();

    const username = document.getElementById('loginUsername').value;
    const password = document.getElementById('loginPassword').value;

    try {
        const response = await fetch('/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, password })
        });

        if (response.ok) {
            window.location.href = 'home.html';
        } else {
            if (response.status === 401) {
                try {
                    const errorResponse = await response.json();
                    if (errorResponse.error === 'invalid_username') {
                        displayErrorMessage('Username not found.');
                    } else if (errorResponse.error === 'incorrect_password') {
                        displayErrorMessage('Incorrect password.');
                    } else {
                        displayErrorMessage('Login failed.');
                    }
                } catch (error) {
                    displayErrorMessage('Login failed.');
                }
            } else {
                displayErrorMessage('Server error. Please try again later.');
            }
        }
    } catch (error) {
        displayErrorMessage('Network error. Please try again later.');
    }
});