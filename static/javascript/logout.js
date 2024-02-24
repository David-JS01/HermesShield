// Espera a que el contenido HTML de la página esté completamente cargado
document.addEventListener("DOMContentLoaded", function() {
    // Obtén el botón de logout por su ID
    var logoutBtn = document.getElementById("boton-logout");

    // Agrega un listener de evento clic al botón de logout
    logoutBtn.addEventListener("click", function() {
        // Redirige al usuario a la página "/logout"
        window.location.href = "/logout";
    });
});
