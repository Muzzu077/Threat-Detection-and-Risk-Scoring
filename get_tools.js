const fs = require('fs');
const cp = require('child_process');

const server = cp.spawn('npx', ['-y', 'reactbits-mcp-server'], { stdio: ['pipe', 'pipe', 'inherit'] });

let buffer = '';

server.stdout.on('data', (data) => {
    buffer += data.toString();
    const lines = buffer.split('\n');
    buffer = lines.pop();
    for (const line of lines) {
        if (!line.trim()) continue;
        try {
            const parsed = JSON.parse(line);
            if (parsed.id === 1) {
                server.stdin.write(JSON.stringify({
                    jsonrpc: "2.0",
                    id: 2,
                    method: "tools/call",
                    params: {
                        name: "get_component",
                        arguments: {
                            componentName: "StarBorder",
                            category: "Animations"
                        }
                    }
                }) + '\n');
            } else if (parsed.id === 2) {
                const content = parsed.result.content[0].text;
                fs.mkdirSync('./frontend/src/components/ReactBits', { recursive: true });
                fs.writeFileSync('./frontend/src/components/ReactBits/StarBorder.jsx', content);
                
                server.stdin.write(JSON.stringify({
                    jsonrpc: "2.0",
                    id: 3,
                    method: "tools/call",
                    params: {
                        name: "get_component",
                        arguments: {
                            componentName: "Particles",
                            category: "Backgrounds"
                        }
                    }
                }) + '\n');
            } else if (parsed.id === 3) {
                const content = parsed.result.content[0].text;
                fs.writeFileSync('./frontend/src/components/ReactBits/Particles.jsx', content);
                console.log('Saved Particles and StarBorder');
                process.exit(0);
            }
        } catch (e) {
        }
    }
});

const initMsg = {
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: {
        protocolVersion: "2024-11-05",
        capabilities: {},
        clientInfo: { name: "test", version: "1.0" }
    }
};

server.stdin.write(JSON.stringify(initMsg) + '\n');
