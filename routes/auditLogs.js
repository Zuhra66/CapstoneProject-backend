const { pool } = require('../db');

class AuditLogger {
  static async log(event) {
    try {
      let userId = event.userId;

      if (userId && userId.includes('google-oauth2|')) {
        userId = null;
      }

      const query = `
        INSERT INTO audit_logs (
          user_id,
          user_email,
          auth0_user_id,
          user_role,
          action,
          event_category,
          entity_type,
          entity_id,
          resource_name,
          status,
          ip_address,
          user_agent,
          meta,
          created_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NOW())
        RETURNING id, created_at;
      `;

      const values = [
        userId,
        event.userEmail,
        event.auth0UserId || event.userId,
        event.userRole,
        event.eventType,
        event.eventCategory,
        event.resourceType,
        event.resourceId,
        event.resourceName,
        event.status || 'success',
        event.ipAddress,
        event.userAgent,
        event.additionalData ? JSON.stringify(event.additionalData) : null
      ];

      const result = await pool.query(query, values);
      return result.rows[0];

    } catch (error) {
      throw error;
    }
  }

  static async getLogs(filters = {}, page = 1, limit = 50) {
    try {
      const offset = (page - 1) * limit;

      const whereConditions = [];
      const params = [];
      let paramCount = 1;

      if (filters.userId) {
        whereConditions.push(`user_id = $${paramCount}`);
        params.push(filters.userId);
        paramCount++;
      }

      if (filters.userEmail) {
        whereConditions.push(`user_email ILIKE $${paramCount}`);
        params.push(`%${filters.userEmail}%`);
        paramCount++;
      }

      if (filters.eventType) {
        whereConditions.push(`action ILIKE $${paramCount}`);
        params.push(`%${filters.eventType}%`);
        paramCount++;
      }

      if (filters.eventCategory) {
        whereConditions.push(`event_category = $${paramCount}`);
        params.push(filters.eventCategory);
        paramCount++;
      }

      if (filters.resourceType) {
        whereConditions.push(`entity_type = $${paramCount}`);
        params.push(filters.resourceType);
        paramCount++;
      }

      if (filters.resourceId) {
        whereConditions.push(`entity_id = $${paramCount}`);
        params.push(filters.resourceId);
        paramCount++;
      }

      if (filters.startDate) {
        whereConditions.push(`DATE(created_at) >= $${paramCount}`);
        params.push(filters.startDate);
        paramCount++;
      }

      if (filters.endDate) {
        whereConditions.push(`DATE(created_at) <= $${paramCount}`);
        params.push(filters.endDate);
        paramCount++;
      }

      if (filters.status) {
        whereConditions.push(`status = $${paramCount}`);
        params.push(filters.status);
        paramCount++;
      }

      if (filters.search) {
        whereConditions.push(`(
          user_email ILIKE $${paramCount} OR
          action ILIKE $${paramCount} OR
          entity_type ILIKE $${paramCount} OR
          resource_name ILIKE $${paramCount}
        )`);
        params.push(`%${filters.search}%`);
        paramCount++;
      }

      const whereClause = whereConditions.length > 0
          ? `WHERE ${whereConditions.join(' AND ')}`
          : '';

      const countQuery = `SELECT COUNT(*) as total FROM audit_logs ${whereClause}`;
      const countResult = await pool.query(countQuery, params);
      const totalItems = parseInt(countResult.rows[0].total);

      const paginationParams = [...params, limit, offset];

      const query = `
        SELECT 
          id,
          user_id,
          user_email,
          user_role,
          auth0_user_id,
          action as event_type,
          event_category,
          entity_type as resource_type,
          entity_id as resource_id,
          resource_name,
          status,
          ip_address,
          user_agent,
          meta as additional_data,
          created_at
        FROM audit_logs 
        ${whereClause}
        ORDER BY created_at DESC 
        LIMIT $${paramCount} OFFSET $${paramCount + 1}
      `;

      const result = await pool.query(query, paginationParams);

      return {
        logs: result.rows,
        pagination: {
          currentPage: page,
          totalPages: Math.ceil(totalItems / limit),
          totalItems,
          itemsPerPage: limit
        }
      };

    } catch (error) {
      return {
        logs: [],
        pagination: {
          currentPage: page,
          totalPages: 1,
          totalItems: 0,
          itemsPerPage: limit
        }
      };
    }
  }

  static async logAdminAction(adminUser, actionType, targetUser = null, resource = null, details = {}, ipAddress = null, userAgent = null) {
    try {
      let adminEmail = adminUser.email || 'unknown@empowermed.com';

      if (!adminEmail || adminEmail === 'unknown@empowermed.com') {
        try {
          const userQuery = await pool.query(
              'SELECT email, first_name, last_name FROM users WHERE id = $1',
              [adminUser.id]
          );
          if (userQuery.rows.length > 0) {
            adminEmail = userQuery.rows[0].email;
          }
        } catch (emailError) {
        }
      }

      const enhancedDetails = {
        ...details,
        admin_email: adminEmail,
        admin_name: adminUser.name || `${adminUser.first_name || ''} ${adminUser.last_name || ''}`.trim(),
        action_timestamp: new Date().toISOString(),
        ip_address: ipAddress,
        user_agent: userAgent
      };

      if (targetUser) {
        enhancedDetails.target_user_id = targetUser.id;
        enhancedDetails.target_email = targetUser.email;
        enhancedDetails.target_name = targetUser.name || `${targetUser.first_name || ''} ${targetUser.last_name || ''}`.trim();
      }

      if (resource) {
        enhancedDetails.resource_type = resource.type;
        enhancedDetails.resource_id = resource.id;
        enhancedDetails.resource_name = resource.name;
      }

      if (actionType.includes('USER_')) {
        enhancedDetails.resource_type = 'user';
      } else if (actionType.includes('PATIENT_')) {
        enhancedDetails.resource_type = 'patient';
      } else if (actionType.includes('APPOINTMENT_')) {
        enhancedDetails.resource_type = 'appointment';
      } else if (actionType.includes('DOCUMENT_')) {
        enhancedDetails.resource_type = 'document';
      }

      const query = `
      INSERT INTO admin_audit_logs (
        admin_user_id, 
        action_type, 
        target_user_id, 
        details, 
        ip_address, 
        user_agent, 
        created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, NOW())
      RETURNING id
    `;

      const values = [
        adminUser.id,
        actionType,
        targetUser ? targetUser.id : null,
        JSON.stringify(enhancedDetails),
        ipAddress,
        userAgent
      ];

      const result = await pool.query(query, values);
      return result.rows[0];
    } catch (error) {
      return null;
    }
  }

  static async logLogin(user, ipAddress, userAgent, status = 'success', error = null) {
    try {
      return await AuditLogger.log({
        userId: user?.id || user?.sub,
        userEmail: user?.email,
        userRole: user?.role || 'user',
        auth0UserId: user?.sub || user?.auth0_id,
        eventType: 'USER_LOGIN',
        eventCategory: 'authentication',
        eventDescription: `User login ${status}`,
        resourceType: 'user',
        resourceId: user?.id || user?.sub,
        resourceName: user?.email || 'unknown',
        ipAddress,
        userAgent,
        status,
        errorMessage: error?.message
      });
    } catch (logError) {
    }
  }

  static async logLogout(user, ipAddress, userAgent) {
    try {
      return await AuditLogger.log({
        userId: user?.id || user?.sub,
        userEmail: user?.email,
        userRole: user?.role,
        auth0UserId: user?.sub || user?.auth0_id,
        eventType: 'USER_LOGOUT',
        eventCategory: 'authentication',
        eventDescription: 'User logged out',
        resourceType: 'user',
        resourceId: user?.id || user?.sub,
        resourceName: user?.email,
        ipAddress,
        userAgent,
        status: 'success'
      });
    } catch (error) {
    }
  }

  static async logLoginAttempt(user, success, ipAddress, userAgent, error = null) {
    try {
      return await AuditLogger.log({
        userId: user?.id || user?.sub,
        userEmail: user?.email,
        userRole: user?.role || 'user',
        auth0UserId: user?.sub || user?.auth0_id,
        eventType: success ? 'USER_LOGIN' : 'LOGIN_FAILURE',
        eventCategory: 'authentication',
        eventDescription: success ? 'User login successful' : `Login failed: ${error?.message || 'Invalid credentials'}`,
        resourceType: 'user',
        resourceId: user?.id || user?.sub,
        resourceName: user?.email || 'unknown',
        ipAddress,
        userAgent,
        status: success ? 'success' : 'failure',
        errorMessage: error?.message
      });
    } catch (logError) {
    }
  }

  static async logUserManagement(adminUser, action, targetUser, changes = {}, ipAddress = null, userAgent = null) {
    const actionType = `USER_${action.toUpperCase()}`;
    const details = {
      action: action,
      target_user_email: targetUser.email,
      target_user_name: `${targetUser.first_name || ''} ${targetUser.last_name || ''}`.trim(),
      changes: changes,
      operation: `${action} user`
    };

    return await AuditLogger.logAdminAction(
        adminUser,
        actionType,
        targetUser,
        { type: 'user', id: targetUser.id, name: targetUser.email },
        details,
        ipAddress,
        userAgent
    );
  }

  static async logUserCreate(adminUser, targetUser, userData, ipAddress = null, userAgent = null) {
    return await AuditLogger.logUserManagement(
        adminUser,
        'CREATE',
        targetUser,
        {
          new_user_data: {
            email: targetUser.email,
            first_name: targetUser.first_name,
            last_name: targetUser.last_name,
            role: targetUser.role,
            is_active: targetUser.is_active
          },
          provided_data: userData
        },
        ipAddress,
        userAgent
    );
  }

  static async logUserUpdate(adminUser, targetUser, oldData, newData, ipAddress = null, userAgent = null) {
    const changes = {};

    if (oldData.email !== newData.email) {
      changes.email = { from: oldData.email, to: newData.email };
    }
    if (oldData.first_name !== newData.first_name) {
      changes.first_name = { from: oldData.first_name, to: newData.first_name };
    }
    if (oldData.last_name !== newData.last_name) {
      changes.last_name = { from: oldData.last_name, to: newData.last_name };
    }
    if (oldData.role !== newData.role) {
      changes.role = { from: oldData.role, to: newData.role };
    }
    if (oldData.is_active !== newData.is_active) {
      changes.is_active = { from: oldData.is_active, to: newData.is_active };
    }

    return await AuditLogger.logUserManagement(
        adminUser,
        'UPDATE',
        targetUser,
        {
          old_data: oldData,
          new_data: newData,
          changes: changes
        },
        ipAddress,
        userAgent
    );
  }

  static async logUserDelete(adminUser, targetUser, ipAddress = null, userAgent = null) {
    return await AuditLogger.logUserManagement(
        adminUser,
        'DELETE',
        targetUser,
        {
          deleted_user_data: {
            email: targetUser.email,
            first_name: targetUser.first_name,
            last_name: targetUser.last_name,
            role: targetUser.role,
            id: targetUser.id
          }
        },
        ipAddress,
        userAgent
    );
  }

  static async logUserStatusChange(adminUser, targetUser, oldStatus, newStatus, reason = null, ipAddress = null, userAgent = null) {
    return await AuditLogger.logUserManagement(
        adminUser,
        'STATUS_CHANGE',
        targetUser,
        {
          status_change: {
            from: oldStatus,
            to: newStatus,
            reason: reason
          }
        },
        ipAddress,
        userAgent
    );
  }

  static async logUserRoleChange(adminUser, targetUser, oldRole, newRole, ipAddress = null, userAgent = null) {
    return await AuditLogger.logUserManagement(
        adminUser,
        'ROLE_CHANGE',
        targetUser,
        {
          role_change: {
            from: oldRole,
            to: newRole
          }
        },
        ipAddress,
        userAgent
    );
  }

  static async logUserPasswordReset(adminUser, targetUser, ipAddress = null, userAgent = null) {
    return await AuditLogger.logUserManagement(
        adminUser,
        'PASSWORD_RESET',
        targetUser,
        {
          action: 'admin_password_reset'
        },
        ipAddress,
        userAgent
    );
  }

  static async logAccess(adminUser, resourceType, resourceId, resourceName, action, ipAddress = null, userAgent = null) {
    try {
      return await AuditLogger.log({
        userId: adminUser.id,
        userEmail: adminUser.email,
        auth0UserId: adminUser.auth0_id,
        userRole: adminUser.role,
        eventType: `${resourceType.toUpperCase()}_${action.toUpperCase()}`,
        eventCategory: 'access',
        resourceType: resourceType,
        resourceId: resourceId,
        resourceName: resourceName,
        status: 'success',
        ipAddress: ipAddress,
        userAgent: userAgent
      });
    } catch (error) {
    }
  }

  static async logDataModification(user, resourceType, resourceId, resourceName, action, oldValue, newValue, changes) {
    try {
      return await AuditLogger.log({
        userId: user?.id || user?.sub,
        userEmail: user?.email,
        userRole: user?.role,
        auth0UserId: user?.sub || user?.auth0_id,
        eventType: `DATA_${action.toUpperCase()}`,
        eventCategory: 'modification',
        eventDescription: `User ${action}d ${resourceType}: ${resourceName}`,
        resourceType,
        resourceId,
        resourceName,
        oldValue,
        newValue,
        changes,
        status: 'success'
      });
    } catch (error) {
    }
  }

  static async logCreate(user, resourceType, resourceId, resourceName, newValue) {
    try {
      return await AuditLogger.logDataModification(user, resourceType, resourceId, resourceName, 'create', null, newValue, null);
    } catch (error) {
    }
  }

  static async logUpdate(user, resourceType, resourceId, resourceName, oldValue, newValue, changes) {
    try {
      return await AuditLogger.logDataModification(user, resourceType, resourceId, resourceName, 'update', oldValue, newValue, changes);
    } catch (error) {
    }
  }

  static async logDelete(user, resourceType, resourceId, resourceName, oldValue) {
    try {
      return await AuditLogger.logDataModification(user, resourceType, resourceId, resourceName, 'delete', oldValue, null, null);
    } catch (error) {
    }
  }

  static async logSecurityEvent(user, eventType, description, severity = 'medium', ipAddress = null, userAgent = null) {
    try {
      return await AuditLogger.log({
        userId: user?.id || user?.sub,
        userEmail: user?.email,
        userRole: user?.role,
        auth0UserId: user?.sub || user?.auth0_id,
        eventType: `SECURITY_${eventType}`,
        eventCategory: 'security',
        eventDescription: description,
        resourceType: 'system',
        ipAddress,
        userAgent,
        status: severity === 'high' ? 'failure' : 'warning'
      });
    } catch (error) {
    }
  }

  static async logSystemEvent(eventType, description, details = null) {
    try {
      return await AuditLogger.log({
        userId: null,
        userEmail: null,
        userRole: null,
        auth0UserId: null,
        eventType: `SYSTEM_${eventType}`,
        eventCategory: 'system',
        eventDescription: description,
        resourceType: 'system',
        additionalData: details || {}
      });
    } catch (error) {
    }
  }

  static async getLogById(logId) {
    try {
      const query = `
        SELECT 
          id,
          user_id,
          user_email,
          user_role,
          auth0_user_id,
          action as event_type,
          event_category,
          entity_type as resource_type,
          entity_id as resource_id,
          resource_name,
          ip_address,
          user_agent,
          meta as metadata,
          status,
          error_message,
          created_at
        FROM audit_logs 
        WHERE id = $1
      `;

      const result = await pool.query(query, [logId]);

      if (result.rows.length === 0) {
        return null;
      }

      const log = result.rows[0];

      return {
        ...log,
        metadata: log.metadata ? JSON.parse(log.metadata) : {}
      };

    } catch (error) {
      throw new Error(`Failed to get audit log: ${error.message}`);
    }
  }

  static async generateComplianceReport(startDate, endDate) {
    try {
      const summaryQuery = `
        SELECT 
          COALESCE(event_category, 'uncategorized') as event_category,
          COALESCE(status, 'unknown') as status,
          COUNT(*) as count
        FROM audit_logs
        WHERE created_at BETWEEN $1 AND $2
        GROUP BY event_category, status
        ORDER BY event_category, status
      `;

      const userActivityQuery = `
        SELECT 
          user_email,
          user_role,
          COUNT(*) as total_events,
          COUNT(CASE WHEN status = 'failure' THEN 1 END) as failed_events,
          COUNT(CASE WHEN event_category = 'access' THEN 1 END) as access_events,
          COUNT(CASE WHEN event_category = 'modification' THEN 1 END) as modification_events,
          MIN(created_at) as first_activity,
          MAX(created_at) as last_activity
        FROM audit_logs
        WHERE created_at BETWEEN $1 AND $2
          AND user_email IS NOT NULL
        GROUP BY user_email, user_role
        ORDER BY total_events DESC
        LIMIT 50
      `;

      const securityQuery = `
        SELECT 
          id,
          action as event_type,
          user_email,
          ip_address,
          created_at,
          error_message
        FROM audit_logs
        WHERE created_at BETWEEN $1 AND $2
          AND event_category = 'security'
          AND status IN ('failure', 'warning')
        ORDER BY created_at DESC
        LIMIT 100
      `;

      const resourcesQuery = `
        SELECT 
          entity_type as resource_type,
          resource_name,
          COUNT(*) as access_count,
          COUNT(DISTINCT user_email) as unique_users
        FROM audit_logs
        WHERE created_at BETWEEN $1 AND $2
          AND entity_type IS NOT NULL
          AND event_category IN ('access', 'modification')
        GROUP BY entity_type, resource_name
        ORDER BY access_count DESC
        LIMIT 20
      `;

      const [summaryResult, userActivityResult, securityResult, resourcesResult] = await Promise.all([
        pool.query(summaryQuery, [startDate, endDate]),
        pool.query(userActivityQuery, [startDate, endDate]),
        pool.query(securityQuery, [startDate, endDate]),
        pool.query(resourcesQuery, [startDate, endDate])
      ]);

      const totalEvents = summaryResult.rows.reduce((sum, row) => sum + parseInt(row.count), 0);
      const failedEvents = summaryResult.rows
      .filter(row => row.status === 'failure')
      .reduce((sum, row) => sum + parseInt(row.count), 0);

      return {
        report: {
          period: {
            startDate,
            endDate,
            durationDays: Math.ceil((new Date(endDate) - new Date(startDate)) / (1000 * 60 * 60 * 24))
          },
          generatedAt: new Date().toISOString(),
          summary: {
            byCategory: summaryResult.rows.reduce((acc, row) => {
              const category = row.event_category;
              const status = row.status;
              const count = parseInt(row.count);

              if (!acc[category]) {
                acc[category] = { total: 0, success: 0, failure: 0, warning: 0, unknown: 0 };
              }
              acc[category][status] = count;
              acc[category].total += count;
              return acc;
            }, {}),
            totals: {
              totalEvents,
              failedEvents,
              successRate: totalEvents > 0 ? ((totalEvents - failedEvents) / totalEvents * 100).toFixed(2) : 0
            }
          },
          userActivity: userActivityResult.rows,
          securityIncidents: securityResult.rows,
          topResources: resourcesResult.rows,
          compliance: {
            totalEvents,
            hasAuthenticationLogs: summaryResult.rows.some(row => row.event_category === 'authentication'),
            hasAccessLogs: summaryResult.rows.some(row => row.event_category === 'access'),
            hasModificationLogs: summaryResult.rows.some(row => row.event_category === 'modification'),
            securityIncidentsCount: securityResult.rows.length,
            uniqueUsers: userActivityResult.rows.length,
            meetsHIPAARequirements: summaryResult.rows.some(row =>
                ['authentication', 'access', 'modification', 'security'].includes(row.event_category)
            )
          }
        }
      };

    } catch (error) {
      throw new Error(`Failed to generate compliance report: ${error.message}`);
    }
  }

  static async cleanupExpiredLogs() {
    try {
      const query = `
        DELETE FROM audit_logs 
        WHERE expires_at < NOW()
        RETURNING COUNT(*) as deleted_count
      `;

      const result = await pool.query(query);
      const deletedCount = parseInt(result.rows[0].deleted_count);

      if (deletedCount > 0) {
        await AuditLogger.logSystemEvent('CLEANUP', `Cleaned up ${deletedCount} expired audit logs`);
      }

      return { deletedCount };

    } catch (error) {
      throw new Error(`Failed to cleanup expired logs: ${error.message}`);
    }
  }

  static async exportLogsToCSV(filters = {}) {
    try {
      const { logs } = await AuditLogger.getLogs(filters, 1, 1000000);

      if (logs.length === 0) {
        return '';
      }

      const headers = [
        'ID', 'Timestamp', 'User Email', 'User Role', 'Event Type',
        'Event Category', 'Resource Type', 'Resource ID', 'Resource Name',
        'IP Address', 'Status', 'Error Message'
      ];

      const rows = logs.map(log => [
        log.id,
        new Date(log.created_at).toISOString(),
        log.user_email || '',
        log.user_role || '',
        log.event_type,
        log.event_category || '',
        log.resource_type || '',
        log.resource_id || '',
        log.resource_name || '',
        log.ip_address || '',
        log.status,
        log.error_message ? `"${log.error_message.replace(/"/g, '""')}"` : ''
      ]);

      const csvContent = [
        headers.join(','),
        ...rows.map(row => row.join(','))
      ].join('\n');

      return csvContent;

    } catch (error) {
      throw new Error(`Failed to export logs: ${error.message}`);
    }
  }

  static async getAdminLogs(filters = {}, page = 1, limit = 50) {
    try {
      const offset = (page - 1) * limit;

      const whereConditions = [];
      const params = [];
      let paramCount = 1;

      if (filters.actionType) {
        whereConditions.push(`action_type ILIKE $${paramCount}`);
        params.push(`%${filters.actionType}%`);
        paramCount++;
      }

      if (filters.startDate) {
        whereConditions.push(`DATE(created_at) >= $${paramCount}`);
        params.push(filters.startDate);
        paramCount++;
      }

      if (filters.endDate) {
        whereConditions.push(`DATE(created_at) <= $${paramCount}`);
        params.push(filters.endDate);
        paramCount++;
      }

      if (filters.search) {
        whereConditions.push(`(
        action_type ILIKE $${paramCount}
      )`);
        params.push(`%${filters.search}%`);
        paramCount++;
      }

      const whereClause = whereConditions.length > 0
          ? `WHERE ${whereConditions.join(' AND ')}`
          : '';

      const countQuery = `SELECT COUNT(*) as total FROM admin_audit_logs ${whereClause}`;
      const countResult = await pool.query(countQuery, params);
      const totalItems = parseInt(countResult.rows[0].total);

      const paginationParams = [...params, limit, offset];

      const query = `
      SELECT 
        id,
        admin_user_id,
        action_type,
        target_user_id,
        details,
        ip_address,
        user_agent,
        created_at
      FROM admin_audit_logs 
      ${whereClause}
      ORDER BY created_at DESC 
      LIMIT $${paramCount} OFFSET $${paramCount + 1}
    `;

      const result = await pool.query(query, paginationParams);

      const userCache = new Map();

      const getUserInfo = async (userId) => {
        if (!userId) return null;

        if (userCache.has(userId)) {
          return userCache.get(userId);
        }

        try {
          const userResult = await pool.query(
              'SELECT id, email, first_name, last_name FROM users WHERE id = $1',
              [userId]
          );

          const userInfo = userResult.rows.length > 0 ? userResult.rows[0] : null;
          userCache.set(userId, userInfo);
          return userInfo;
        } catch (error) {
          return null;
        }
      };

      const logs = [];

      for (const log of result.rows) {
        try {
          const adminInfo = await getUserInfo(log.admin_user_id);
          const admin_email = adminInfo?.email || 'unknown@empowermed.com';
          const admin_name = adminInfo ? `${adminInfo.first_name || ''} ${adminInfo.last_name || ''}`.trim() : '';

          let target_email = '';
          let target_name = '';
          let targetInfo = null;

          if (log.target_user_id) {
            targetInfo = await getUserInfo(log.target_user_id);
            target_email = targetInfo?.email || '';
            target_name = targetInfo ? `${targetInfo.first_name || ''} ${targetInfo.last_name || ''}`.trim() : '';
          }

          let details = {};
          if (log.details && typeof log.details === 'object' && Object.keys(log.details).length > 0) {
            details = log.details;
          } else if (log.details && typeof log.details === 'string' && log.details.trim()) {
            try {
              details = JSON.parse(log.details);
            } catch (parseError) {
            }
          }

          const action_type = log.action_type || '';
          let inferred_target = 'N/A';
          let inferred_resource = 'System';
          let inferred_resource_type = '';

          if (action_type.includes('USER_')) {
            inferred_resource_type = 'user';
            if (action_type.includes('CREATE') || action_type.includes('ADD')) {
              inferred_resource = 'User Account';
              inferred_target = target_email || 'New User';
            } else if (action_type.includes('UPDATE') || action_type.includes('EDIT')) {
              inferred_resource = 'User Account';
              inferred_target = target_email || 'User';
            } else if (action_type.includes('DELETE') || action_type.includes('REMOVE')) {
              inferred_resource = 'User Account';
              inferred_target = target_email || 'User';
            } else if (action_type.includes('VIEW') || action_type.includes('GET')) {
              inferred_resource = 'User Profile';
              inferred_target = target_email || 'User';
            }
          } else if (action_type.includes('PATIENT_')) {
            inferred_resource_type = 'patient';
            inferred_resource = 'Patient Record';
            inferred_target = target_email || 'Patient';
          } else if (action_type.includes('APPOINTMENT_')) {
            inferred_resource_type = 'appointment';
            inferred_resource = 'Appointment';
            inferred_target = 'Appointment';
          } else if (action_type.includes('DOCUMENT_') || action_type.includes('FILE_')) {
            inferred_resource_type = 'document';
            inferred_resource = 'Document/File';
            inferred_target = 'Document';
          } else if (action_type.includes('SETTING_') || action_type.includes('CONFIG_')) {
            inferred_resource_type = 'settings';
            inferred_resource = 'System Settings';
            inferred_target = 'Configuration';
          } else if (action_type.includes('DASHBOARD')) {
            inferred_resource_type = 'dashboard';
            inferred_resource = 'Dashboard';
            inferred_target = 'Statistics/Reports';
          } else if (action_type.includes('LOG_') || action_type.includes('AUDIT_')) {
            inferred_resource_type = 'audit';
            inferred_resource = 'Audit Logs';
            inferred_target = 'Log Records';
          } else if (action_type.includes('EMAIL_') || action_type.includes('NOTIFICATION_')) {
            inferred_resource_type = 'communication';
            inferred_resource = 'Email/Notification';
            inferred_target = target_email || 'Recipient';
          } else if (action_type.includes('LOGIN') || action_type.includes('AUTH')) {
            inferred_resource_type = 'authentication';
            inferred_resource = 'Authentication';
            inferred_target = 'System Access';
          }

          const final_target = target_email || target_name || inferred_target;
          const final_resource = details.resource_name || details.resourceName || inferred_resource;
          const final_resource_type = details.resource_type || details.resourceType || inferred_resource_type;

          const formattedLog = {
            id: log.id,
            admin_user_id: log.admin_user_id,
            admin_email: admin_email,
            admin_name: admin_name,
            action_type: action_type,
            target_user_id: log.target_user_id,
            target_email: target_email,
            target_name: target_name,
            resource_type: final_resource_type,
            resource_name: final_resource,
            details: details,
            ip_address: log.ip_address,
            user_agent: log.user_agent,
            created_at: log.created_at,
            user: admin_email,
            action: this.formatActionForDisplay(action_type),
            target: final_target,
            resource: final_resource,
            ipAddress: log.ip_address
          };

          logs.push(formattedLog);

        } catch (error) {
          logs.push({
            id: log.id,
            user: 'Error',
            action: log.action_type || 'Unknown',
            target: 'Error',
            resource: 'Error',
            created_at: log.created_at,
            details: { error: 'Failed to process log' }
          });
        }
      }

      return {
        logs,
        pagination: {
          currentPage: page,
          totalPages: Math.ceil(totalItems / limit),
          totalItems,
          itemsPerPage: limit
        }
      };

    } catch (error) {
      return {
        logs: [],
        pagination: {
          currentPage: page,
          totalPages: 1,
          totalItems: 0,
          itemsPerPage: limit
        }
      };
    }
  }

  static formatActionForDisplay(actionType) {
    if (!actionType) return 'Unknown Action';

    let formatted = actionType.replace(/_/g, ' ');

    formatted = formatted.toLowerCase()
    .split(' ')
    .map(word => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ');

    return formatted;
  }
}

module.exports = AuditLogger;