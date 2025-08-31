import { Injectable } from '@nestjs/common';

@Injectable()
export class AppService {
  getHello(): string {
    return 'IronVeil Identity Security Scanner API';
  }
}
