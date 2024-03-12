function uploadFiles() {
    const fileInput = document.getElementById('fileInput');
    const files = fileInput.files;

    if (files.length === 0) {
        alert('Please select files to upload.');
        return;
    }

    const formData = new FormData();
    for (let i = 0; i < files.length; i++) {
        formData.append('myFiles[]', files[i]);
    }

    fetch('/upload-encrypted', { //Endpoint to upload files
        method: 'POST',
        body: formData
    })
    .then(response => {
        if (response.ok) {
            return response.json();
        } else {
            throw new Error('Failed to upload files.');
        }
    })
    .then(data => {
        displayFiles(data.files);
    })
    .catch(error => {
        console.error('Error:', error);
    });
}
//fetch files
async function fetchFiles() {
    try {
        const response = await fetch('/list-files');
        if (response.ok) {
            const data = await response.json();
            displayFiles(data.files);
        } else {
            console.error('Failed to fetch files');
        }
    } catch (error) {
        console.error('Error:', error);
    }
}

//to display files
function displayFiles(files) {
    const fileListTable = document.getElementById('fileList');
    const tbody = fileListTable.querySelector('tbody');
    tbody.innerHTML = ''; // Clear the table body content before adding files

   
    files.forEach(file => {
        const row = tbody.insertRow();
        const fileNameCell = row.insertCell();
        const actionCell = row.insertCell();

        const downloadLink = document.createElement('a');
        downloadLink.textContent = file;
        downloadLink.href = `/download/${encodeURIComponent(file)}`; // Set the download link endpoint
        downloadLink.setAttribute('download', ''); // Add download attribute


        fileNameCell.appendChild(downloadLink); // Append the download link to the cell

        const deleteButton = document.createElement('button');
        deleteButton.textContent = 'Delete';
        deleteButton.onclick = function() {
            deleteFile(file);
        };

        actionCell.appendChild(deleteButton);
    });
}


async function deleteFile(filename) {
    try {
        const response = await fetch(`/delete/${filename}`, {
            method: 'DELETE'
        });
        if (response.ok) {
            // Refresh file list after deletion
            fetchFiles();
        } else {
            console.error('Failed to delete file');
        }
    } catch (error) {
        console.error('Error:', error);
    }
}



// Call fetchFiles() initially to display uploaded files on page load
fetchFiles();

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

