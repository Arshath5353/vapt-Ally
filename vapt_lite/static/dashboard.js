document.addEventListener("DOMContentLoaded", function() {
    // Read the embedded JSON data from the template
    const rawData = document.getElementById('chart-data').textContent;
    const counts = JSON.parse(rawData);

    const ctx = document.getElementById('vulnChart').getContext('2d');
    
    new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low'],
            datasets: [{
                data: [counts.Critical, counts.High, counts.Medium, counts.Low],
                backgroundColor: [
                    '#DC2626', // Critical
                    '#EA580C', // High
                    '#D97706', // Medium
                    '#2563EB'  // Low
                ],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: { position: 'bottom' }
            }
        }
    });
});