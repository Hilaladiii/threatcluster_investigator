import os

def generate_report():    
    os.makedirs("output", exist_ok=True)
    
    output_path = os.path.join("output", "report.html")
    with open(output_path, "w", encoding="utf-8") as f:
        html_content = """
        <!DOCTYPE html>
        <html lang="id">
        <head>
            <meta charset="UTF-8" />
            <title>Hasil Clustering: Anomali</title>

            <!-- DataTables CSS + Bootstrap -->
            <link
            rel="stylesheet"
            href="https://cdn.datatables.net/1.13.4/css/dataTables.bootstrap5.min.css"
            />
            <link
            href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css"
            rel="stylesheet"
            />

            <style>
            body {
                background-color: #f8f9fa;
                font-family: "Segoe UI", sans-serif;
            }
            .container {
                margin-top: 50px;
            }
            .card {
                padding: 20px;
                border-radius: 15px;
                box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
            }
            table.dataTable td {
                white-space: normal !important;
                word-wrap: break-word;
                max-width: 300px;
            }
            th,
            td {
                text-align: center;
                vertical-align: middle;
            }
            .filter-container {
                margin-bottom: 15px;
            }
            </style>
        </head>
        <body>
            <div class="container">
            <div class="card">
                <h3 class="text-center mb-4">📊 Hasil Clustering</h3>

                <!-- Filter container -->
                <div class="filter-container d-flex">
                <!-- Filter cluster -->
                <div class="d-flex">
                    <label class="me-2">Filter Cluster:</label>
                    <select id="clusterFilter" class="form-select w-auto">
                    <option value="">Semua</option>
                    </select>
                </div>

                <!-- Filter label -->
                <div class="d-flex">
                    <label class="me-2">Filter Label:</label>
                    <select id="labelFilter" class="form-select w-auto">
                    <option value="">Semua</option>
                    <option value="Normal">Normal</option>
                    <option value="Suspected_As_An_Attack">Suspected_As_An_Attack</option>
                    </select>
                </div>
                </div>

                <div class="table-responsive">
                <table id="anomaliTable" class="table table-striped table-bordered">
                    <thead>
                    <tr>
                        <th>ip</th>
                        <th>time</th>
                        <th>status</th>
                        <th>url</th>
                        <th>user_agent</th>
                        <th>cluster</th>
                        <th>label</th>
                    </tr>
                    </thead>
                    <tbody></tbody>
                </table>
                </div>
            </div>
            </div>

            <!-- jQuery + DataTables JS -->
            <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
            <script src="https://cdn.datatables.net/1.13.4/js/jquery.dataTables.min.js"></script>
            <script src="https://cdn.datatables.net/1.13.4/js/dataTables.bootstrap5.min.js"></script>

            <!-- PapaParse untuk load CSV -->
            <script src="https://cdnjs.cloudflare.com/ajax/libs/PapaParse/5.4.1/papaparse.min.js"></script>

            <script>
            $(document).ready(function () {
                Papa.parse("report.csv", {
                download: true,
                header: true,
                complete: function (results) {
                    let table = $("#anomaliTable").DataTable({
                    data: results.data,
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
                    });

                    // --- Filter Cluster ---
                    let clusters = [...new Set(results.data.map((row) => row.cluster))].filter(
                    (c) => c !== undefined && c !== ""
                    );
                    clusters.forEach((c) => {
                    $("#clusterFilter").append(
                        `<option value="${c}">Cluster ${c}</option>`
                    );
                    });

                    $("#clusterFilter").on("change", function () {
                    let val = $(this).val();
                    if (val) {
                        table.column(5).search("^" + val + "$", true, false).draw();
                    } else {
                        table.column(5).search("").draw();
                    }
                    });

                    // --- Filter Label ---
                    $("#labelFilter").on("change", function () {
                    let val = $(this).val();
                    if (val) {
                        table.column(6).search("^" + val + "$", true, false).draw();
                    } else {
                        table.column(6).search("").draw();
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
