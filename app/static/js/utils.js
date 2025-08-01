//=====================================================
//  Utility front-end functions
//=====================================================


// Trigger when page loads...
window.onload = (event) => {

    //--------------------------------------------------
    // Prevent duplicate submission of forms
    //--------------------------------------------------
    document.querySelectorAll('form:has(button)').forEach(form => {
        // Get the form's button
        const button = form.querySelector('button')
        // When the form is submitted...
        form.addEventListener('submit', (e) => {
            // Already submitted?
            if (button.ariaBusy === true) {
                // Prevent re-submit
                e.preventDefault()
            }
            else {
                // Show button as busy
                button.ariaBusy = true
                button.innerText = 'Please Wait...'
            }
        });
    });
};

document.addEventListener("DOMContentLoaded", () => {
    const successMessages = document.querySelectorAll('#messages .message.success');

    successMessages.forEach((message) => {
        setTimeout(() => {
            message.classList.add('fade-out');
        }, 3000); // 3 seconds before fade starts

        // Optional: remove element from DOM after animation
        message.addEventListener('animationend', () => {
            message.remove();
        });
    });
});

