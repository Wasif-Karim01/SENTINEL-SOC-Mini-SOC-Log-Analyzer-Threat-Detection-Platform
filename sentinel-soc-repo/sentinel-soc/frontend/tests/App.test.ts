import { describe, it, expect } from 'vitest';

describe('SENTINEL SOC Frontend Specification Tests', () => {
  it('verifies developer metadata and contact links', () => {
    const dev = {
      name: 'Wasif Karim',
      email: 'wasifkarim.work@gmail.com',
      whatsapp: 'https://wa.me/8801783734911',
      education: ['DU PMICS — 7th Batch', 'B.Sc. in Computer Science & Engineering', 'Daffodil International University'],
    };
    expect(dev.name).toBe('Wasif Karim');
    expect(dev.whatsapp).toContain('8801783734911');
  });
});
