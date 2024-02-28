// Carga la biblioteca Google Charts
google.charts.load('current', {'packages':['gauge']});
// Llama a la función de dibujo después de cargar la biblioteca
google.charts.setOnLoadCallback(drawChart);
console.log("llega aqui")

function drawChart() {
    // Obtén el nivel de fiabilidad del correo electrónico (por ejemplo, del servidor o de una API)
    //var fiabilidad = 80; // Ejemplo: nivel de fiabilidad del 80%
    fiabilidad=parseFloat(fiabilidad);
    console.log(fiabilidad)
    // Crea un nuevo gráfico de gauge
    var data = google.visualization.arrayToDataTable([
        ['Label', 'Value'],
        ['Peligrosidad', 100 - fiabilidad]
    ]);

    var options = {
        width: 250, height: 250,
        redFrom: 60, redTo: 100,
        yellowFrom:30, yellowTo: 60,
        greenFrom: 0, greenTo: 30,
        minorTicks: 5
    };

    // Dibuja el gráfico en el contenedor especificado
    var chart = new google.visualization.Gauge(document.getElementById('myChart'));
    chart.draw(data, options);
    console.log(data)
}
