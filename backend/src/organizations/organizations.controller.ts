import {
  Controller,
  Get,
  Post,
  Put,
  Body,
  UseGuards,
  Request,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
} from '@nestjs/swagger';
import { ThrottlerGuard } from '@nestjs/throttler';
import { OrganizationsService } from './organizations.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import {
  CreateOrganizationDto,
  UpdateOrganizationDto,
  OrganizationResponseDto,
  InviteUserDto,
  UserProfileResponseDto,
} from './dto/organization.dto';
import { BaseResponseDto } from '../common/dto/base.dto';

@ApiTags('organizations')
@Controller('organizations')
@UseGuards(ThrottlerGuard)
export class OrganizationsController {
  private readonly logger = new Logger(OrganizationsController.name);

  constructor(private organizationsService: OrganizationsService) {}

  @Post()
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('JWT')
  @ApiOperation({
    summary: 'Create new organization',
    description: 'Create a new organization and associate the current user as admin.',
  })
  @ApiResponse({
    status: HttpStatus.CREATED,
    description: 'Organization created successfully',
    type: OrganizationResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.CONFLICT,
    description: 'Organization slug already exists',
  })
  async createOrganization(
    @Body() createDto: CreateOrganizationDto,
    @Request() req: any,
  ): Promise<OrganizationResponseDto> {
    this.logger.log(`Creating organization "${createDto.name}" for user ${req.user.id}`);
    return this.organizationsService.createOrganization(createDto, req.user);
  }

  @Get()
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('JWT')
  @ApiOperation({
    summary: 'Get organization details',
    description: 'Retrieve details of the authenticated user\'s organization.',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Organization details retrieved successfully',
    type: OrganizationResponseDto,
  })
  async getOrganization(@Request() req: any): Promise<OrganizationResponseDto> {
    return this.organizationsService.getOrganization(req.user);
  }

  @Put()
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('JWT')
  @ApiOperation({
    summary: 'Update organization',
    description: 'Update organization settings. Requires admin role.',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Organization updated successfully',
    type: OrganizationResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.FORBIDDEN,
    description: 'Only organization admins can update settings',
  })
  async updateOrganization(
    @Body() updateDto: UpdateOrganizationDto,
    @Request() req: any,
  ): Promise<OrganizationResponseDto> {
    this.logger.log(`Updating organization ${req.user.organizationId} by user ${req.user.id}`);
    return this.organizationsService.updateOrganization(updateDto, req.user);
  }

  @Get('users')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('JWT')
  @ApiOperation({
    summary: 'Get organization users',
    description: 'Retrieve list of all users in the organization.',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Organization users retrieved successfully',
    type: [UserProfileResponseDto],
  })
  async getOrganizationUsers(@Request() req: any): Promise<UserProfileResponseDto[]> {
    return this.organizationsService.getOrganizationUsers(req.user);
  }

  @Post('invite')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('JWT')
  @ApiOperation({
    summary: 'Invite user to organization',
    description: 'Send an invitation to join the organization. Requires admin role.',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Invitation sent successfully',
    type: BaseResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.FORBIDDEN,
    description: 'Only organization admins can invite users',
  })
  @ApiResponse({
    status: HttpStatus.CONFLICT,
    description: 'User is already a member of this organization',
  })
  async inviteUser(
    @Body() inviteDto: InviteUserDto,
    @Request() req: any,
  ): Promise<BaseResponseDto> {
    this.logger.log(`Inviting user ${inviteDto.email} to organization ${req.user.organizationId}`);
    const result = await this.organizationsService.inviteUser(inviteDto, req.user);
    return new BaseResponseDto(result.success, result.message);
  }
}