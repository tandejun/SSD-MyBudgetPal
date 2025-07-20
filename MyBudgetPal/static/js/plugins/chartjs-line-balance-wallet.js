//Transaction Graph 
var ctx = document.getElementById("chartjsBalanceWallet")
ctx.height = 100
var myChart = new Chart(ctx, {
    type: 'bar',
    data: {
        labels: ["A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "AA", "AB",],
        datasets: [{
            label: '',
            data: [5, 6, 4.5, 5.5, 3, 6, 4.5, 6, 8, 3, 5.5, 4, 6, 9, 12, 4, 3, 6, 4.5, 6, 8, 4.5, 5, 6, 4.5, 5.5,],
            backgroundColor: '#4c84ff',
        }]
    },
    options: {
        legend: {
            display: false
        },
        scales: {
            xAxes: [{
                gridLines: {
                    drawBorder: false,
                    display: false
                },
                ticks: {
                    display: false, // hide main x-axis line
                    beginAtZero: true
                },
                barPercentage: 1,
                categoryPercentage: 0.2
            }],
            yAxes: [{
                gridLines: {
                    drawBorder: false, // hide main y-axis line
                    display: false
                },
                ticks: {
                    display: false,
                    beginAtZero: true
                },
            }]
        },
        tooltips: {
            enabled: false
        }
    }
})
