import React, { useState, useRef, useEffect } from "react";

function App() {
    const [curlCommand, setCurlCommand] = useState("");
    const [log, setLog] = useState("");
    const [loading, setLoading] = useState(false);
    const [tamper, setTamper] = useState("");
    const [level, setLevel] = useState("3");
    const [risk, setRisk] = useState("2");
    const [randomAgent, setRandomAgent] = useState(false);

    const logRef = useRef(null);
    const [infoCount, setInfoCount] = useState(0);
    const [warningCount, setWarningCount] = useState(0);
    const [errorCount, setErrorCount] = useState(0);
    const [injectionCount, setInjectionCount] = useState(0);
    const [injectionDetails, setInjectionDetails] = useState([]);


    useEffect(() => {
        if (logRef.current) {
            logRef.current.scrollTop = logRef.current.scrollHeight;
        }
    }, [log]);

    useEffect(() => {
        const info = (log.match(/\[INFO\]/g) || []).length;
        const warning = (log.match(/\[WARNING\]/g) || []).length;
        const error = (log.match(/\[ERROR\]/g) || []).length;
        let foundInjections = 0;

        setInfoCount(info);
        setWarningCount(warning);
        setErrorCount(error);
        const lines = log.split("\n");
        const details = [];
        let currentParam = null;

        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            const paramMatch = line.match(/^Parameter:\s*(\w+)\s+\((GET|POST|COOKIE|HEADER|URI)\)/i);
            if (paramMatch) {
                currentParam = paramMatch[1];
            }

            const typeMatch = line.match(/^\s*Type:\s*(.+)$/i);
            const titleMatch = lines[i + 1]?.match(/^\s*Title:\s*(.+)$/i);

            if (typeMatch && titleMatch && currentParam) {
                details.push({
                    param: currentParam,
                    type: typeMatch[1],
                    title: titleMatch[1],
                });
                foundInjections++;
            }
        }
        setInjectionCount(foundInjections); // ✅ เพิ่มการนับ injection จริง
        setInjectionDetails(details);

    }, [log]);

    const runSqlmap = async () => {
        setLoading(true);
        setLog("");

        try {
            const response = await fetch("http://localhost:8000/run", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ curl: curlCommand, tamper, level, risk, random_agent: randomAgent }),
            });

            if (!response.ok) {
                const err = await response.json();
                setLog(`Error: ${err.detail}`);
            } else {
                const reader = response.body.getReader();
                const decoder = new TextDecoder();
                let done = false;

                while (!done) {
                    const { value, done: doneReading } = await reader.read();
                    done = doneReading;
                    if (value) {
                        const chunk = decoder.decode(value, { stream: true });
                        setLog((prev) => prev + chunk);
                    }
                }
            }
        } catch (err) {
            setLog(`Fetch error: ${err.message}`);
        }

        setLoading(false);
    };

    function parseLogsToColoredLines(logText) {
        const lines = logText.split("\n");
        return lines.map((line, idx) => {
            let color = "black";
            if (line.includes("[INFO]")) color = "green";
            else if (line.includes("[WARNING]")) color = "orange";
            else if (line.includes("[ERROR]")) color = "red";

            return (
                <div key={idx} style={{ color, whiteSpace: "pre-wrap", fontFamily: "monospace", fontSize: 12 }}>
                    {line}
                </div>
            );
        });
    }

    const tamperOptions = [
        "",
        "apostrophemask", "base64encode", "between", "bluecoat", "chardoubleencode", "charencode", "charunicodeencode",
        "equaltolike", "escapequotes", "greatest", "halfversionedmorekeywords", "ifnull2ifisnull", "lowercase",
        "modsecurityversioned", "modsecurityzeroversioned", "multiplespaces", "nonrecursivereplacement", "overlongutf8",
        "percentage", "randomcase", "randomcomments", "securesphere", "space2comment", "space2dash", "space2hash",
        "space2morehash", "space2mssqlblank", "space2mssqlhash", "space2plus", "space2randomblank", "symboliclogical",
        "unionalltounion", "unmagicquotes", "uppercase", "varnish", "versionedkeywords", "versionedmorekeywords"
    ];

    return (
        <div className="p-4 max-w-7xl mx-auto">
            <h1 className="text-2xl font-bold mb-4">SQL Injection Tester</h1>

            <div className="flex flex-col lg:flex-row gap-6">
                {/* ฝั่งซ้าย: textarea + controls */}
                <div className="flex-1 w-full lg:w-auto">
                    <textarea
                        className="w-full border rounded p-2 font-mono resize-y min-h-[120px]"
                        rows={6}
                        placeholder="Paste your curl command here..."
                        value={curlCommand}
                        onChange={(e) => setCurlCommand(e.target.value)}
                    />

                    <div className="mt-2 flex flex-wrap gap-4 items-center">
                        <div>
                            <label className="block text-sm font-medium">Level</label>
                            <select
                                value={level}
                                onChange={(e) => setLevel(e.target.value)}
                                className="border rounded p-1"
                            >
                                {[1, 2, 3, 4, 5].map((v) => (
                                    <option key={v} value={v}>
                                        {v}
                                    </option>
                                ))}
                            </select>
                        </div>
                        <div>
                            <label className="block text-sm font-medium">Risk</label>
                            <select
                                value={risk}
                                onChange={(e) => setRisk(e.target.value)}
                                className="border rounded p-1"
                            >
                                {[1, 2, 3].map((v) => (
                                    <option key={v} value={v}>
                                        {v}
                                    </option>
                                ))}
                            </select>
                        </div>
                        <div>
                            <label className="block text-sm font-medium">Tamper</label>
                            <select
                                className="border rounded p-1"
                                value={tamper}
                                onChange={(e) => setTamper(e.target.value)}
                            >
                                {tamperOptions.map((opt) => (
                                    <option key={opt} value={opt}>
                                        {opt || "-- Select Tamper Script --"}
                                    </option>
                                ))}
                            </select>
                        </div>
                        <div className="flex items-center gap-2 mt-6">
                            <input
                                type="checkbox"
                                checked={randomAgent}
                                onChange={(e) => setRandomAgent(e.target.checked)}
                            />
                            <label className="text-sm">Random Agent</label>
                        </div>
                    </div>

                    <button
                        className="mt-2 px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 disabled:opacity-50"
                        disabled={loading || !curlCommand.trim()}
                        onClick={runSqlmap}
                    >
                        {loading ? "Running..." : "Run Test"}
                    </button>

                    <pre
                        ref={logRef}
                        className="mt-4 p-4 bg-gray-100 rounded h-[350px] lg:h-96 overflow-auto whitespace-pre-wrap"
                    >
                        {log ? parseLogsToColoredLines(log) : "Logs will appear here..."}
                    </pre>
                    {injectionDetails.length > 0 && (
                        <div className="mt-4 bg-white shadow rounded p-4 max-w-full w-full">
                            <div className="font-semibold text-lg mb-2">🛡️ SQL Injection Detected</div>
                            <ul className="list-disc list-inside text-sm break-words">
                                {injectionDetails.map((item, idx) => (
                                    <li key={idx}>
                                        <span className="text-red-700 font-medium">Parameter "{item.param}"</span> - {item.type} →{" "}
                                        <span className="text-gray-800 italic">{item.title}</span>
                                    </li>
                                ))}
                            </ul>
                        </div>
                    )}
                </div>

                {/* ฝั่งขวา: Summary */}
                <div className="w-full lg:w-64 flex-shrink-0">
                    <div className="bg-white shadow rounded p-4 space-y-4">
                        <div className="text-lg font-semibold">Summary</div>
                        <div className="text-green-700 font-medium">Info: {infoCount}</div>
                        <div className="text-yellow-600 font-medium">Warning: {warningCount}</div>
                        <div className="text-red-700 font-medium">Injection: {injectionCount}</div>
                        <div className="text-red-600 font-medium">Error: {errorCount}</div>
                    </div>
                </div>
            </div>
        </div>

    );
}

export default App;
