const esbuild = require('esbuild');
const path = require('path');

async function build() {
    try {
        await esbuild.build({
            entryPoints: [path.resolve(__dirname, '../static/js/app.js')],
            bundle: true,
            minify: true,
            sourcemap: true,
            outfile: path.resolve(__dirname, '../static/js/bundle.min.js'),
            format: 'esm',
            target: ['es2020'],
            loader: { '.js': 'jsx' },
        });
        console.log('Build completed successfully');
    } catch (error) {
        console.error('Build failed:', error);
        process.exit(1);
    }
}

build(); 