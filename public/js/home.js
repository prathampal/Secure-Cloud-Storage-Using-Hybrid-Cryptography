 //  for handling logout
 document.getElementById('logoutButton').addEventListener('click', async () => {
    const response = await fetch('/logout', {
        method: 'GET',
        credentials: 'include' // Ensure credentials are sent with the request
    });

    if (response.ok) {
        // Redirect to the login page after successful logout
        window.location.href = 'index.html'; // Redirect to the login page
    } else {
        // Handle logout error
        console.error('Logout failed.');
    }
});