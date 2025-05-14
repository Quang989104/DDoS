const socket = io("http://localhost:5000");

// Kết nối WebSocket
socket.on("connect", () => {
    console.log("Connected to WebSocket server");
});

// Lắng nghe sự kiện "new_traffic_log" từ server
socket.on("new_traffic_log", (data) => {
    console.log("New traffic log received:", data);
    updateChart(data);
});

// Hàm cập nhật dữ liệu vào biểu đồ (giả sử bạn dùng Chart.js)
function updateChart(data) {
    myChart.data.labels.push(data.timestamp);
    myChart.data.datasets[0].data.push(data.packet_count);
    myChart.update();
}
