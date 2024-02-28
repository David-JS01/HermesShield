google.charts.load('current', {'packages':['corechart']});
google.charts.setOnLoadCallback(drawChart);

        function drawChart() {
            var datos = [['Dominio', 'Número de Blacklists']];

            // Recorrer el array de objetos y añadir los datos al array de datos del gráfico
            servidores.forEach(function(objeto) {
                datos.push([objeto.nombre, objeto.blacklists]);
            });
            var data = google.visualization.arrayToDataTable(datos);

            var options = {
                width: 600, height: 300,
                title: 'Número de Blacklists por Servidor',
                hAxis: {title: 'Servidor', titleTextStyle: {color: 'blue'}, textStyle: {fontSize: 10}},
                vAxis: {title: 'Número de Blacklists', titleTextStyle: {color: 'blue'}}
            };

            var chart = new google.visualization.ColumnChart(document.getElementById('blacklistSer'));
            chart.draw(data, options);
        }