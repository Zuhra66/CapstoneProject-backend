// routes/auditLogs.js - COMPLETE WORKING VERSION
const express = require('express');
const router = express.Router();
const AuditLogger = require('../services/auditLogger');
const { checkJwt, attachAdminUser, requireAdmin } = require('../middleware/admin-check');

/**
 * GET /api/audit/logs - Get audit logs (Admin only)
 * Now uses enhanced audit_logs table
 */
// routes/auditLogs.js - Update the main /logs route
router.get('/logs', checkJwt, attachAdminUser, requireAdmin, async (req, res) => {
  try {
    const {
      page = 1,
      limit = 50,
      userId,
      userEmail,
      eventType,
      eventCategory,
      resourceType,
      resourceId,
      startDate,
      endDate,
      status,
      search
    } = req.query;

    console.log('🔍 [GET /logs] Request received with query:', req.query);

    // Validate input
    const pageNum = parseInt(page);
    const limitNum = parseInt(limit);

    if (isNaN(pageNum) || pageNum < 1) {
      console.log('❌ [GET /logs] Invalid page number:', page);
      return res.status(400).json({
        success: false,
        error: 'Invalid page number'
      });
    }

    if (isNaN(limitNum) || limitNum < 1 || limitNum > 500) {
      console.log('❌ [GET /logs] Invalid limit:', limit);
      return res.status(400).json({
        success: false,
        error: 'Limit must be between 1 and 500'
      });
    }

    console.log('🔍 [GET /logs] Calling AuditLogger.getLogs() with:', {
      eventCategory,
      status,
      startDate,
      endDate,
      search,
      page: pageNum,
      limit: limitNum
    });

    // Get logs from enhanced table
    const logs = await AuditLogger.getLogs({
      userId,
      userEmail,
      eventType,
      eventCategory,
      resourceType,
      resourceId,
      startDate,
      endDate,
      status,
      search
    }, pageNum, limitNum);

    console.log(` [GET /logs] Retrieved ${logs.logs?.length || 0} audit logs`);
    console.log(`[GET /logs] Total items in pagination: ${logs.pagination?.totalItems || 0}`);

    // Try to log this access (but don't fail if it doesn't work)
    try {
      await AuditLogger.logAccess(
          req.adminUser,
          'audit_log',
          null,
          'Audit Logs',
          'view',
          req.ip,
          req.headers['user-agent']
      );
    } catch (logError) {
      console.warn('⚠️ [GET /logs] Failed to log access:', logError.message);
    }

    res.json({
      success: true,
      ...logs,
      message: `Retrieved ${logs.logs?.length || 0} audit logs`
    });

  } catch (error) {
    console.error('❌ [GET /logs] Get audit logs error:', error);
    console.error('❌ [GET /logs] Error stack:', error.stack);

    // Try to log the error (but don't fail if it doesn't work)
    try {
      await AuditLogger.logSecurityEvent(
          req.adminUser,
          'AUDIT_LOG_ERROR',
          `Failed to retrieve audit logs: ${error.message}`,
          'medium',
          req.ip,
          req.headers['user-agent']
      );
    } catch (logError) {
      console.error('❌ [GET /logs] Failed to log error:', logError);
    }

    res.status(500).json({
      success: false,
      error: 'Failed to retrieve audit logs',
      details: process.env.NODE_ENV === 'development' ? {
        message: error.message,
        stack: error.stack
      } : undefined
    });
  }
});
router.get('/admin', checkJwt, attachAdminUser, requireAdmin, async (req, res) => {
  try {
    const {
      page = 1,
      limit = 10,
      actionType = '',
      adminEmail = '',
      targetEmail = '',
      startDate = '',
      endDate = '',
      search = ''
    } = req.query;

    console.log('🔍 [API /admin] Query params:', req.query);

    const filters = {
      actionType,
      adminEmail,
      targetEmail,
      startDate,
      endDate,
      search
    };

    const result = await AuditLogger.getAdminLogs(filters, parseInt(page), parseInt(limit));

    console.log(`✅ [API /admin] Returning ${result.logs.length} admin logs, total: ${result.pagination.totalItems}`);

    // Format response for frontend
    const formattedLogs = result.logs.map(log => ({
      id: log.id,
      timestamp: log.created_at,
      user: log.user || log.admin_email, // Use user field for display
      action: log.action_type,
      target: log.target || 'N/A',
      resource: log.resource || 'System',
      details: log.details,
      ipAddress: log.ip_address,
      userAgent: log.user_agent,
      // Additional fields for frontend if needed
      adminEmail: log.admin_email,
      adminName: log.admin_name,
      targetEmail: log.target_email,
      targetName: log.target_name,
      resourceType: log.resource_type,
      resourceName: log.resource_name,
      resourceId: log.resource_id
    }));

    res.json({
      success: true,
      logs: formattedLogs,
      pagination: {
        total: result.pagination.totalItems,
        page: result.pagination.currentPage,
        totalPages: result.pagination.totalPages,
        limit: parseInt(limit)
      }
    });

  } catch (error) {
    console.error('❌ [API /admin] Error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});
router.get('/test-admin-logs', checkJwt, attachAdminUser, requireAdmin, async (req, res) => {
  try {
    const { pool } = require('../db');

    // Test 1: Get sample admin logs
    const sampleQuery = await pool.query(`
      SELECT 
        al.id,
        al.admin_user_id,
        u.email as admin_email,
        al.action_type,
        al.target_user_id,
        (
          SELECT email 
          FROM users 
          WHERE id = al.target_user_id
        ) as target_email,
        al.details,
        al.created_at
      FROM admin_audit_logs al
      LEFT JOIN users u ON al.admin_user_id = u.id::uuid
      ORDER BY al.created_at DESC 
      LIMIT 5
    `);

    // Test 2: Count logs
    const countQuery = await pool.query('SELECT COUNT(*) as total FROM admin_audit_logs');

    // Test 3: Check table columns
    const columnsQuery = await pool.query(`
      SELECT column_name, data_type 
      FROM information_schema.columns 
      WHERE table_name = 'admin_audit_logs'
      ORDER BY ordinal_position
    `);

    // Test 4: Use getAdminLogs method
    const auditLoggerResult = await AuditLogger.getAdminLogs({}, 1, 5);

    res.json({
      success: true,
      tableStructure: columnsQuery.rows,
      sampleData: sampleQuery.rows,
      totalLogs: countQuery.rows[0].total,
      getAdminLogsResult: {
        logsCount: auditLoggerResult.logs.length,
        totalItems: auditLoggerResult.pagination.totalItems,
        firstLog: auditLoggerResult.logs[0] || null
      },
      note: 'Admin Actions tab should show data if getAdminLogsResult.logsCount > 0'
    });

  } catch (error) {
    console.error('❌ Test admin logs error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});
/**
 * GET /api/audit/admin-logs - Get admin audit logs (from admin_audit_logs table)
 */
router.get('/admin-logs', checkJwt, attachAdminUser, requireAdmin, async (req, res) => {
  try {
    const {
      page = 1,
      limit = 20,
      eventCategory = '',
      status = '',
      startDate = '',
      endDate = '',
      search = ''
    } = req.query;

    console.log('🔍 [API /admin-logs] Query params:', req.query);

    // Map frontend filters to admin log filters
    const filters = {
      actionType: search || '',
      startDate,
      endDate,
      search
    };

    const result = await AuditLogger.getAdminLogs(filters, parseInt(page), parseInt(limit));

    console.log(`✅ [API /admin-logs] Returning ${result.logs.length} admin logs, total: ${result.pagination.totalItems}`);

    // Format response for frontend
    const formattedLogs = result.logs.map(log => ({
      id: log.id,
      timestamp: log.created_at,
      user: log.user,
      action: log.action,
      target: log.target,
      resource: log.resource,
      ipAddress: log.ipAddress,
      userAgent: log.user_agent,
      details: log.details,
      // Additional info for details modal if needed
      _raw: {
        adminEmail: log.admin_email,
        adminName: log.admin_name,
        targetEmail: log.target_email,
        targetName: log.target_name,
        resourceType: log.resource_type,
        resourceName: log.resource_name,
        actionType: log.action_type
      }
    }));

    res.json({
      success: true,
      logs: formattedLogs,
      pagination: {
        total: result.pagination.totalItems,
        page: result.pagination.currentPage,
        totalPages: result.pagination.totalPages,
        limit: parseInt(limit)
      }
    });

  } catch (error) {
    console.error('❌ [API /admin-logs] Error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});
router.get('/admin-logs-debug', checkJwt, attachAdminUser, requireAdmin, async (req, res) => {
  try {
    const { pool } = require('../db');
    const { limit = 10 } = req.query;

    // Get admin logs with their action types
    const result = await pool.query(`
      SELECT 
        id,
        action_type,
        admin_user_id,
        target_user_id,
        details,
        created_at,
        pg_typeof(details) as details_type,
        CASE 
          WHEN details IS NULL OR details = 'null'::jsonb THEN 'null'
          WHEN jsonb_typeof(details) = 'object' AND jsonb_object_length(details) = 0 THEN 'empty_object'
          WHEN jsonb_typeof(details) = 'object' THEN 'has_data'
          ELSE 'unknown'
        END as details_status
      FROM admin_audit_logs 
      WHERE action_type ILIKE '%USER%'
      ORDER BY created_at DESC 
      LIMIT $1
    `, [parseInt(limit)]);

    // Also get a sample of all action types
    const actionTypes = await pool.query(`
      SELECT 
        action_type,
        COUNT(*) as count
      FROM admin_audit_logs 
      GROUP BY action_type
      ORDER BY count DESC
      LIMIT 20
    `);

    res.json({
      success: true,
      user_related_logs: result.rows.map(log => ({
        id: log.id,
        action_type: log.action_type,
        admin_user_id: log.admin_user_id,
        target_user_id: log.target_user_id,
        details: log.details,
        details_type: log.details_type,
        details_status: log.details_status,
        created_at: log.created_at
      })),
      action_types_summary: actionTypes.rows,
      recommendation: 'We need to log more details when admin performs actions'
    });

  } catch (error) {
    console.error('Admin logs debug error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * GET /api/audit/report - Generate compliance report (Admin only)
 * Now uses enhanced audit_logs table
 */
router.get('/report', checkJwt, attachAdminUser, requireAdmin, async (req, res) => {
  try {
    let { startDate, endDate = new Date().toISOString() } = req.query;

    // Validate startDate
    if (!startDate) {
      return res.status(400).json({
        success: false,
        error: 'startDate parameter is required'
      });
    }

    // Validate date format
    const startDateObj = new Date(startDate);
    const endDateObj = new Date(endDate);

    if (isNaN(startDateObj.getTime())) {
      return res.status(400).json({
        success: false,
        error: 'Invalid startDate format. Use ISO format (YYYY-MM-DD)'
      });
    }

    if (isNaN(endDateObj.getTime())) {
      return res.status(400).json({
        success: false,
        error: 'Invalid endDate format. Use ISO format (YYYY-MM-DD)'
      });
    }

    // Ensure startDate is before endDate
    if (startDateObj > endDateObj) {
      return res.status(400).json({
        success: false,
        error: 'startDate must be before endDate'
      });
    }

    // Limit report to max 365 days
    const maxDays = 365;
    const daysDiff = Math.ceil((endDateObj - startDateObj) / (1000 * 60 * 60 * 24));

    if (daysDiff > maxDays) {
      return res.status(400).json({
        success: false,
        error: `Report period cannot exceed ${maxDays} days`
      });
    }

    const report = await AuditLogger.generateComplianceReport(startDate, endDate);

    // Log report generation
    try {
      await AuditLogger.logAccess(
          req.adminUser,
          'audit_report',
          null,
          'Compliance Report',
          'generate',
          req.ip,
          req.headers['user-agent']
      );
    } catch (logError) {
      console.warn('Failed to log access:', logError.message);
    }

    res.json({
      success: true,
      ...report,
      message: `Compliance report generated for ${daysDiff} day(s)`
    });

  } catch (error) {
    console.error('Generate report error:', error);

    try {
      await AuditLogger.logSecurityEvent(
          req.adminUser,
          'REPORT_GENERATION_ERROR',
          `Failed to generate compliance report: ${error.message}`,
          'medium',
          req.ip,
          req.headers['user-agent']
      );
    } catch (logError) {
      console.error('Failed to log security event:', logError);
    }

    res.status(500).json({
      success: false,
      error: 'Failed to generate compliance report',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

/**
 * GET /api/audit/export - Export logs to CSV (Admin only)
 * Now uses enhanced audit_logs table
 */
router.get('/export', checkJwt, attachAdminUser, requireAdmin, async (req, res) => {
  try {
    const {
      startDate,
      endDate = new Date().toISOString(),
      eventCategory,
      status
    } = req.query;

    // Validate dates if provided
    if (startDate && isNaN(new Date(startDate).getTime())) {
      return res.status(400).json({
        success: false,
        error: 'Invalid startDate format'
      });
    }

    if (endDate && isNaN(new Date(endDate).getTime())) {
      return res.status(400).json({
        success: false,
        error: 'Invalid endDate format'
      });
    }

    const filters = {};
    if (startDate) filters.startDate = startDate;
    if (endDate) filters.endDate = endDate;
    if (eventCategory) filters.eventCategory = eventCategory;
    if (status) filters.status = status;

    const csvContent = await AuditLogger.exportLogsToCSV(filters);

    if (!csvContent) {
      return res.status(404).json({
        success: false,
        error: 'No logs found to export'
      });
    }

    // Log export
    try {
      await AuditLogger.logAccess(
          req.adminUser,
          'audit_log',
          null,
          'Audit Logs',
          'export',
          req.ip,
          req.headers['user-agent']
      );
    } catch (logError) {
      console.warn('Failed to log access:', logError.message);
    }

    // Set headers for CSV download
    const filename = `audit-logs-${new Date().toISOString().split('T')[0]}.csv`;

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(csvContent);

  } catch (error) {
    console.error('Export logs error:', error);

    try {
      await AuditLogger.logSecurityEvent(
          req.adminUser,
          'EXPORT_ERROR',
          `Failed to export audit logs: ${error.message}`,
          'medium',
          req.ip,
          req.headers['user-agent']
      );
    } catch (logError) {
      console.error('Failed to log security event:', logError);
    }

    res.status(500).json({
      success: false,
      error: 'Failed to export audit logs',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

/**
 * POST /api/audit/log - Manually log an audit event (Admin only)
 * Now uses enhanced audit_logs table
 */
router.post('/log', checkJwt, attachAdminUser, requireAdmin, async (req, res) => {
  try {
    const event = req.body;

    // Validate required fields
    if (!event.eventType || !event.eventCategory || !event.eventDescription) {
      return res.status(400).json({
        success: false,
        error: 'Missing required fields: eventType, eventCategory, eventDescription'
      });
    }

    // Add user info from authenticated request
    const enhancedEvent = {
      ...event,
      userId: event.userId || req.adminUser.id,
      userEmail: event.userEmail || req.adminUser.email,
      userRole: event.userRole || req.adminUser.role,
      auth0UserId: event.auth0UserId || req.adminUser.auth0_id
    };

    const auditLogger = new AuditLogger();
    const result = await auditLogger.log(enhancedEvent);

    // Log this manual logging event
    try {
      await AuditLogger.logAccess(
          req.adminUser,
          'audit_log',
          result?.id || 'manual',
          'Manual Audit Log',
          'create',
          req.ip,
          req.headers['user-agent']
      );
    } catch (logError) {
      console.warn('Failed to log access:', logError.message);
    }

    res.json({
      success: true,
      logId: result?.id,
      message: 'Audit event logged successfully'
    });

  } catch (error) {
    console.error('Manual log error:', error);

    try {
      await AuditLogger.logSecurityEvent(
          req.adminUser,
          'MANUAL_LOG_ERROR',
          `Failed to manually log audit event: ${error.message}`,
          'medium',
          req.ip,
          req.headers['user-agent']
      );
    } catch (logError) {
      console.error('Failed to log security event:', logError);
    }

    res.status(500).json({
      success: false,
      error: 'Failed to log audit event',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

/**
 * DELETE /api/audit/cleanup - Clean up expired logs (Admin only)
 */
router.delete('/cleanup', checkJwt, attachAdminUser, requireAdmin, async (req, res) => {
  try {
    const result = await AuditLogger.cleanupExpiredLogs();

    // Log cleanup
    try {
      await AuditLogger.logSystemEvent(
          'MANUAL_CLEANUP',
          `Manual cleanup performed by ${req.adminUser.email}`
      );
    } catch (logError) {
      console.warn('Failed to log system event:', logError.message);
    }

    res.json({
      success: true,
      ...result,
      message: `Cleaned up ${result.deletedCount} expired audit logs`
    });

  } catch (error) {
    console.error('Cleanup error:', error);

    try {
      await AuditLogger.logSecurityEvent(
          req.adminUser,
          'CLEANUP_ERROR',
          `Failed to cleanup expired logs: ${error.message}`,
          'medium',
          req.ip,
          req.headers['user-agent']
      );
    } catch (logError) {
      console.error('Failed to log security event:', logError);
    }

    res.status(500).json({
      success: false,
      error: 'Failed to cleanup expired logs',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

/**
 * GET /api/audit/stats - Get audit log statistics (Admin only)
 * Now uses enhanced audit_logs table
 */
router.get('/stats', checkJwt, attachAdminUser, requireAdmin, async (req, res) => {
  try {
    const { period = '30days' } = req.query;

    let startDate = new Date();
    switch (period) {
      case '7days':
        startDate.setDate(startDate.getDate() - 7);
        break;
      case '30days':
        startDate.setDate(startDate.getDate() - 30);
        break;
      case '90days':
        startDate.setDate(startDate.getDate() - 90);
        break;
      case '365days':
        startDate.setDate(startDate.getDate() - 365);
        break;
      default:
        startDate.setDate(startDate.getDate() - 30);
    }

    const startDateISO = startDate.toISOString();
    const endDateISO = new Date().toISOString();

    const report = await AuditLogger.generateComplianceReport(startDateISO, endDateISO);

    // Get recent activity
    const recentQuery = `
      SELECT 
        action as event_type,
        user_email,
        resource_name,
        created_at
      FROM audit_logs
      ORDER BY created_at DESC
      LIMIT 10
    `;

    const { pool } = require('../db');
    const recentResult = await pool.query(recentQuery);

    res.json({
      success: true,
      period: {
        start: startDateISO,
        end: endDateISO,
        days: Math.ceil((new Date(endDateISO) - new Date(startDateISO)) / (1000 * 60 * 60 * 24))
      },
      summary: report.report.summary,
      recentActivity: recentResult.rows,
      message: 'Audit statistics retrieved successfully'
    });

  } catch (error) {
    console.error('Get stats error:', error);

    try {
      await AuditLogger.logSecurityEvent(
          req.adminUser,
          'STATS_ERROR',
          `Failed to get audit statistics: ${error.message}`,
          'medium',
          req.ip,
          req.headers['user-agent']
      );
    } catch (logError) {
      console.error('Failed to log security event:', logError);
    }

    res.status(500).json({
      success: false,
      error: 'Failed to get audit statistics',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// routes/auditLogs.js - DEBUGGING ENDPOINT

router.get('/debug-audit', checkJwt, attachAdminUser, requireAdmin, async (req, res) => {
  try {
    const { pool } = require('../db');

    console.log('🔍 [DEBUG AUDIT] Testing audit_logs query...');
    console.log('🔍 [DEBUG AUDIT] Request query params:', req.query);

    // Test 1: Direct simple query
    const simpleQuery = `
      SELECT 
        id,
        user_email,
        action,
        event_category,
        created_at
      FROM audit_logs 
      ORDER BY created_at DESC 
      LIMIT 5
    `;

    const simpleResult = await pool.query(simpleQuery);
    console.log('✅ [DEBUG AUDIT] Simple query result count:', simpleResult.rows.length);
    console.log('📊 [DEBUG AUDIT] Sample rows:', simpleResult.rows);

    // Test 2: Test with getLogs method using current filters
    console.log('🔍 [DEBUG AUDIT] Testing AuditLogger.getLogs() with filters...');
    const logsResult = await AuditLogger.getLogs({
      startDate: req.query.startDate,
      endDate: req.query.endDate,
      eventCategory: req.query.eventCategory,
      status: req.query.status,
      search: req.query.search
    }, 1, 20);

    console.log('✅ [DEBUG AUDIT] getLogs() result count:', logsResult.logs.length);
    console.log('📊 [DEBUG AUDIT] getLogs() pagination:', logsResult.pagination);

    if (logsResult.logs.length > 0) {
      console.log('📊 [DEBUG AUDIT] First log from getLogs():', {
        id: logsResult.logs[0].id,
        user_email: logsResult.logs[0].user_email,
        event_type: logsResult.logs[0].event_type,
        event_category: logsResult.logs[0].event_category,
        created_at: logsResult.logs[0].created_at
      });
    }

    // Test 3: Check exact column names
    const columnCheck = await pool.query(`
      SELECT column_name, data_type
      FROM information_schema.columns 
      WHERE table_name = 'audit_logs'
      ORDER BY ordinal_position;
    `);

    console.log('📊 [DEBUG AUDIT] Table columns:', columnCheck.rows.map(c => c.column_name));

    res.json({
      success: true,
      directQuery: {
        count: simpleResult.rows.length,
        sample: simpleResult.rows
      },
      getLogs: {
        count: logsResult.logs.length,
        pagination: logsResult.pagination,
        sample: logsResult.logs.length > 0 ? logsResult.logs[0] : null
      },
      tableColumns: columnCheck.rows.map(c => c.column_name),
      debugInfo: {
        filtersUsed: {
          startDate: req.query.startDate,
          endDate: req.query.endDate,
          eventCategory: req.query.eventCategory,
          status: req.query.status,
          search: req.query.search
        }
      }
    });

  } catch (error) {
    console.error('❌ [DEBUG AUDIT] Error:', error);
    console.error('❌ [DEBUG AUDIT] Error stack:', error.stack);
    res.status(500).json({
      success: false,
      error: error.message,
      stack: error.stack
    });
  }
});
module.exports = router;