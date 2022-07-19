import bearerjwtTest from './suites/bearerjwt.test.js';

describe('***************************\n  ** OAS AUTH TESING SUITE **\n  ***************************', () => {
    const nodeMajor = parseInt(process.version.split('.')[0].replace('v',''));
    
    after(() => {
        process.exit(0);
    });
    
    // Test suites
    if(nodeMajor >= 16) bearerjwtTest();
});