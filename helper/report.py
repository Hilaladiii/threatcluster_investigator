import os

def generate_report():    
    os.makedirs("output", exist_ok=True)
    
    output_path = os.path.join("output", "index.html")
    with open(output_path, "w", encoding="utf-8") as f:
        html_content = """
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8" />
    <title>Dashboard Analisis Anomali</title>

    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" />
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet" />
    <link href="https://cdn.datatables.net/1.13.7/css/dataTables.bootstrap5.min.css" rel="stylesheet" />
    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
    <link href="https://fonts.googleapis.com/css2?family=Lato:ital,wght@0,300;0,400;0,700;0,900&display=swap" rel="stylesheet" />

    <style>
        body {
            font-family: "Lato", "Segoe UI", sans-serif;
            background-color: #f4f7f6;
        }
        .navbar {
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
        }
        .stat-card {
            border: none;
            border-radius: 12px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.07);
            transition: all 0.3s ease;
        }
        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 6px 16px rgba(0, 0, 0, 0.1);
        }
        .stat-card .card-body {
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        .stat-card .stat-icon {
            font-size: 3rem;
            opacity: 0.3;
        }
        .card-title {
            font-weight: 700;
            color: #555;
        }
        .stat-number {
            font-size: 2rem;
            font-weight: 900;
        }
        .main-card {
            border-radius: 15px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
        }        
        tr.row-suspected {
            background-color: #f8d7da !important; /* Bootstrap 'danger' light */
            font-weight: 600;
        }        
        #clusterFilter option[data-suspected="1"] {
            color: #dc3545;
            font-weight: 700;
        }
        /* Styling untuk DataTables */
        table.dataTable td {
            white-space: normal !important;
            word-wrap: break-word;
            max-width: 250px;
            vertical-align: middle;
        }
        table.dataTable th {
            text-align: center;
            vertical-align: middle;
        }
        .filter-container {
            gap: 15px;
        }
        .time-clock {
            display: block;
            font-weight: 700;       
            font-size: 1.05em;      
            color: #212529;         
            line-height: 1.2;
            white-space: nowrap;    
        }
        .time-date {
            display: block;
            font-size: 0.9em;       
            color: #6c757d;         
            line-height: 1.2;
            white-space: nowrap;
        }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-light bg-white sticky-top">
        <div class="container-fluid">
            <a class="navbar-brand" href="#">
                <i class="bi bi-shield-shaded"></i>
                <strong>Analisis Log Server</strong>
            </a>
        </div>
    </nav>

    <div class="container-fluid mt-4">
        <div class="row mb-4">
            <div class="col-xl-3 col-md-6 mb-3">
                <div class="card stat-card border-start border-primary border-5">
                    <div class="card-body">
                        <div>
                            <div class="card-title text-primary text-uppercase">Total Log</div>
                            <div id="totalLogs" class="stat-number">0</div>
                        </div>
                        <i class="bi bi-file-earmark-text stat-icon text-primary"></i>
                    </div>
                </div>
            </div>

            <div class="col-xl-3 col-md-6 mb-3">
                <div class="card stat-card border-start border-info border-5">
                    <div class="card-body">
                        <div>
                            <div class="card-title text-info text-uppercase">Total Cluster</div>
                            <div id="totalClusters" class="stat-number">0</div>
                        </div>
                        <i class="bi bi-boxes stat-icon text-info"></i>
                    </div>
                </div>
            </div>

            <div class="col-xl-3 col-md-6 mb-3">
                <div class="card stat-card border-start border-danger border-5">
                    <div class="card-body">
                        <div>
                            <div class="card-title text-danger text-uppercase">Anomali</div>
                            <div id="totalSuspected" class="stat-number">0</div>
                        </div>
                        <i class="bi bi-bug-fill stat-icon text-danger"></i>
                    </div>
                </div>
            </div>

            <div class="col-xl-3 col-md-6 mb-3">
                <div class="card stat-card border-start border-success border-5">
                    <div class="card-body">
                        <div>
                            <div class="card-title text-success text-uppercase">Normal</div>
                            <div id="totalNormal" class="stat-number">0</div>
                        </div>
                        <i class="bi bi-patch-check-fill stat-icon text-success"></i>
                    </div>
                </div>
            </div>
        </div>

        <div class="row">
            <div class="col-12">
                <div class="card main-card">
                    <div class="card-header bg-white py-3">
                        <h4 class="mb-0">Detail Hasil Clustering</h4>
                    </div>
                    <div class="card-body p-4">
                        <div class="filter-container d-flex flex-wrap align-items-center mb-3">
                            <div class="d-flex align-items-center">
                                <label class="me-2 fw-bold">Cluster:</label>
                                <select id="clusterFilter" class="form-select w-auto">
                                    <option value="">Semua</option>
                                </select>
                            </div>
                            <div class="d-flex align-items-center">
                                <label class="me-2 fw-bold">Label:</label>
                                <select id="labelFilter" class="form-select w-auto">
                                    <option value="">Semua</option>
                                    <option value="Normal">Normal</option>
                                    <option value="Suspected_As_An_Attack">Suspected</option>
                                </select>
                            </div>
                            <div class="ms-auto-md">
                                <span class="badge bg-danger-subtle text-danger-emphasis rounded-pill px-4 py-2">
                                    ⚠ = Cluster mengandung anomali
                                </span>
                            </div>
                        </div>

                        <div class="table-responsive">
                            <table id="anomaliTable" class="table table-striped table-bordered" style="width: 100%">
                                <thead>
                                    <tr>
                                        <th>IP</th>
                                        <th>Time</th>
                                        <th>Status</th>
                                        <th>URL</th>
                                        <th>User Agent</th>
                                        <th>Cluster</th>
                                        <th>Label</th>
                                    </tr>
                                </thead>
                                <tbody></tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/PapaParse/5.4.1/papaparse.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.7/js/jquery.dataTables.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.7/js/dataTables.bootstrap5.min.js"></script>

    <script>
        $(document).ready(function () {
            Papa.parse("report.csv", {
                download: true,
                header: true,
                skipEmptyLines: true, 
                complete: function (results) {
                    const data = results.data;
                    
                    let totalSuspected = 0;
                    let totalNormal = 0;
                    const clusterCounts = {};
                    const clusterHasSuspected = {};

                    data.forEach((row) => {
                        const c = row.cluster;
                        if (c === undefined || c === "") return;

                        if (row.label === "Suspected_As_An_Attack") {
                            totalSuspected++;
                            clusterHasSuspected[c] = true;
                        } else {
                            totalNormal++;
                            clusterHasSuspected[c] = clusterHasSuspected[c] || false;
                        }
                        
                        clusterCounts[c] = (clusterCounts[c] || 0) + 1;
                    });

                    const totalLogs = data.length;
                    const totalClusters = Object.keys(clusterCounts).length;
                    
                    $("#totalLogs").text(totalLogs);
                    $("#totalClusters").text(totalClusters);
                    $("#totalSuspected").text(totalSuspected);
                    $("#totalNormal").text(totalNormal);

                    const table = $("#anomaliTable").DataTable({
                        data: data,
                        columns: [
                            { data: "ip" },
                            { data: "time" },
                            { data: "status" },
                            { data: "url" },
                            { data: "user_agent" },
                            { data: "cluster" },
                            { data: "label" },
                        ],
                        pageLength: 10,
                        scrollX: true,                        
                        columnDefs: [
                        {
                                targets: 1,
                                render: function (data, type, row) {
                                    // Hanya format ulang untuk 'display'
                                    if (type === 'display' && data) {                         

                                        try {                                            
                                            const dateTimeSplit = data.split(' ');
                                            const datePart = dateTimeSplit[0]; // "2019-01-23"
                                            const timePart = dateTimeSplit[1]; // "03:28:35.000000003+00:00"
                                            
                                            const dateComponents = datePart.split('-'); // ["2019", "01", "23"]
                                            const formattedDate = `${dateComponents[2]}-${dateComponents[1]}-${dateComponents[0]}`; // "23-01-2019"

                                            const formattedTime = timePart.substring(0, 8); // "03:28:35"
                                            
                                            return `<span class="time-clock">${formattedTime}</span><span class="time-date">${formattedDate}</span>`;

                                        } catch (e) {                                         
                                            return data; 
                                        }
                                    }                                    
                                    return data;
                                }
                            },
                            {                                
                                targets: 6,
                                render: function (data, type, row) {
                                    if (data === "Suspected_As_An_Attack") {
                                        return '<span class="badge bg-danger">Suspected</span>';
                                    } else {
                                        return '<span class="badge bg-success">Normal</span>';
                                    }
                                },
                            },
                        ],                        
                        createdRow: function (row, data, dataIndex) {
                            if (data.label === "Suspected_As_An_Attack") {
                                $(row).addClass("row-suspected");
                            }
                        },
                    });
                    
                    const clusterKeys = Object.keys(clusterCounts).sort((a, b) => {
                        const na = Number(a),
                            nb = Number(b);
                        if (!isNaN(na) && !isNaN(nb)) return na - nb;
                        return String(a).localeCompare(String(b));
                    });

                    clusterKeys.forEach((c) => {
                        const count = clusterCounts[c];
                        const hasSus = !!clusterHasSuspected[c];
                        const labelText = hasSus ? `Cluster ${c} (${count}) ⚠` : `Cluster ${c} (${count})`;
                        
                        const $opt = $("<option>")
                            .val(c)
                            .text(labelText)
                            .attr("data-suspected", hasSus ? "1" : "0");
                        $("#clusterFilter").append($opt);
                    });

                    
                    function applyExactFilter(columnIndex, value) {
                        if (value) {                    
                            table.column(columnIndex).search("^" + $.fn.dataTable.util.escapeRegex(value) + "$", true, false).draw();
                        } else {
                            table.column(columnIndex).search("").draw();
                        }
                    }

                    $("#clusterFilter").on("change", function () {
                        applyExactFilter(5, $(this).val()); 
                    });

                    $("#labelFilter").on("change", function () {                        
                        let val = $(this).val();
                        if (val === 'Normal') {
                           applyExactFilter(6, 'Normal');
                        } else if (val === 'Suspected_As_An_Attack') {
                           applyExactFilter(6, 'Suspected');
                        } else {
                           applyExactFilter(6, '');
                        }
                    });
                },
            });
        });
    </script>
</body>
</html>
        """
        f.write(html_content)

    print(f"Report berhasil dibuat di: {output_path}")
