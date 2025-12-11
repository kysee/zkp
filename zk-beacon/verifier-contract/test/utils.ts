import * as fs from 'fs';
import path from 'path';

export function projectRoot(startPath = "."): string {
    let currentPath = startPath;

    while (currentPath !==
    path.parse(currentPath).root) {
        if (fs.existsSync(path.join(currentPath,
            'package.json'))) {
            return currentPath;
        }
        currentPath = path.dirname(currentPath);
    }

    throw new Error('not found project root dir');
}