const express = require("express");
const router = express.Router();
const { pool } = require("../db");
const multer = require("multer");
const path = require("path");
const fs = require("fs");

const { checkJwt, attachAdminUser, requireAdmin } = require("../middleware/admin-check");

const uploadsDir = path.join(__dirname, '..', 'uploads', 'blog');
fs.mkdirSync(uploadsDir, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadsDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + '-' + file.originalname.replace(/\s+/g, '-'));
  }
});

const fileFilter = (req, file, cb) => {
  const allowedTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/webp', 'image/gif'];
  if (allowedTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('Invalid file type. Only images are allowed.'), false);
  }
};

const upload = multer({
  storage,
  fileFilter,
  limits: { fileSize: 10 * 1024 * 1024 }
});

function slugify(text) {
  return text
  .toString()
  .toLowerCase()
  .replace(/\s+/g, '-')
  .replace(/[^\w\-]+/g, '')
  .replace(/\-\-+/g, '-')
  .replace(/^-+/, '')
  .replace(/-+$/, '');
}

async function generateUniqueSlug(title) {
  let slug = slugify(title);
  let counter = 1;
  let baseSlug = slug;

  while (true) {
    const { rows } = await pool.query(
        'SELECT id FROM blog_posts WHERE slug = $1 LIMIT 1',
        [slug]
    );

    if (rows.length === 0) return slug;

    slug = `${baseSlug}-${counter}`;
    counter++;
  }
}

// Test route
router.get("/test", (req, res) => {
  res.json({ message: "Blog routes are working!" });
});

// Public routes
router.get("/", async (req, res) => {
  try {
    const { limit = 10, offset = 0, category, featured } = req.query;
    const userId = req.user?.id;

    let whereClause = "WHERE bp.status = 'published'";
    const params = [];
    let paramIndex = 1;

    if (category) {
      whereClause += ` AND LOWER(bp.category) = LOWER($${paramIndex})`;
      params.push(category);
      paramIndex++;
    }

    if (featured === 'true') {
      whereClause += ` AND bp.is_featured = true`;
    }

    const postsQuery = `
      SELECT 
        bp.id,
        bp.title,
        bp.slug,
        bp.excerpt,
        bp.content_md,
        bp.cover_image_url,
        bp.status,
        bp.is_featured,
        bp.view_count,
        bp.published_at,
        bp.created_at,
        bp.updated_at,
        bp.category,
        u.id as author_id,
        CONCAT(u.first_name, ' ', u.last_name) as author_name,
        '' as author_avatar,
        (
          SELECT COUNT(*) 
          FROM blog_likes bl 
          WHERE bl.post_id = bp.id
        ) as like_count,
        ${userId ? `
          EXISTS(
            SELECT 1 
            FROM blog_likes bl 
            WHERE bl.post_id = bp.id AND bl.user_id = $${paramIndex}
          ) as user_liked
        ` : 'FALSE as user_liked'}
      FROM blog_posts bp
      LEFT JOIN users u ON bp.author_id = u.id
      ${whereClause}
      ORDER BY bp.published_at DESC NULLS LAST, bp.created_at DESC
      LIMIT $${userId ? paramIndex + 1 : paramIndex} OFFSET $${userId ? paramIndex + 2 : paramIndex + 1}
    `;

    if (userId) {
      params.push(userId, parseInt(limit), parseInt(offset));
    } else {
      params.push(parseInt(limit), parseInt(offset));
    }

    const { rows: posts } = await pool.query(postsQuery, params);

    const totalQuery = `
      SELECT COUNT(*) 
      FROM blog_posts bp 
      ${whereClause}
    `;
    const { rows: countRows } = await pool.query(
        totalQuery,
        userId ? params.slice(0, -2) : params.slice(0, -2)
    );

    const total = parseInt(countRows[0].count);

    res.json({
      posts: posts.map(post => ({
        ...post,
        excerpt: post.excerpt || (post.content_md ? post.content_md.substring(0, 200) + '...' : ''),
        published_at: post.published_at,
        author: {
          id: post.author_id,
          name: post.author_name,
          avatar: post.author_avatar
        }
      })),
      pagination: {
        total,
        limit: parseInt(limit),
        offset: parseInt(offset),
        hasMore: parseInt(offset) + posts.length < total
      }
    });
  } catch (err) {
    console.error("Blog list error:", err);
    res.status(500).json({ error: "Failed to load blog posts" });
  }
});

// Get post details WITHOUT comments for non-authenticated users
router.get("/:slug", async (req, res) => {
  try {
    const { slug } = req.params;
    const userId = req.user?.id;
    const isAuthenticated = !!userId;

    const postQuery = `
      SELECT 
        bp.*,
        u.id as author_id,
        CONCAT(u.first_name, ' ', u.last_name) as author_name,
        '' as author_avatar,
        (
          SELECT COUNT(*) 
          FROM blog_likes bl 
          WHERE bl.post_id = bp.id
        ) as like_count,
        ${userId ? `
          EXISTS(
            SELECT 1 
            FROM blog_likes bl 
            WHERE bl.post_id = bp.id AND bl.user_id = $2
          ) as user_liked
        ` : 'FALSE as user_liked'}
      FROM blog_posts bp
      LEFT JOIN users u ON bp.author_id = u.id
      WHERE bp.slug = $1 AND bp.status = 'published'
      LIMIT 1
    `;

    const params = [slug];
    if (userId) params.push(userId);

    const { rows } = await pool.query(postQuery, params);

    if (rows.length === 0) {
      return res.status(404).json({ error: "Post not found" });
    }

    const post = rows[0];

    await pool.query(
        'UPDATE blog_posts SET view_count = view_count + 1 WHERE id = $1',
        [post.id]
    );

    // Only load comments if user is authenticated
    let comments = [];
    if (isAuthenticated) {
      const commentsQuery = `
        SELECT 
          bc.*,
          u.id as user_id,
          u.first_name,
          u.last_name
        FROM blog_comments bc
        LEFT JOIN users u ON bc.user_id = u.id
        WHERE bc.post_id = $1 AND bc.is_approved = true
        ORDER BY bc.created_at ASC
      `;

      const { rows: commentRows } = await pool.query(commentsQuery, [post.id]);

      // Format user names
      const formattedComments = commentRows.map(comment => {
        const formattedName = formatUserName(comment.first_name, comment.last_name);
        return {
          ...comment,
          user_name: formattedName,
          user_avatar: null,
        };
      });

      comments = buildCommentTree(formattedComments);
    }

    res.json({
      post: {
        ...post,
        author: {
          id: post.author_id,
          name: post.author_name,
          avatar: post.author_avatar
        }
      },
      comments: comments
    });
  } catch (err) {
    console.error("Blog detail error:", err);
    res.status(500).json({ error: "Failed to load blog post" });
  }
});

function formatUserName(firstName, lastName) {
  if (!firstName && !lastName) return 'Anonymous';
  if (!lastName) return firstName;

  const lastNameInitial = lastName.charAt(0) + '.';
  return `${firstName} ${lastNameInitial}`;
}

function buildCommentTree(comments) {
  const commentMap = new Map();
  const rootComments = [];

  comments.forEach(comment => {
    comment.replies = [];
    commentMap.set(comment.id, comment);

    if (comment.parent_id) {
      const parent = commentMap.get(comment.parent_id);
      if (parent) {
        parent.replies.push(comment);
      }
    } else {
      rootComments.push(comment);
    }
  });

  return rootComments;
}

// Like a post - using checkJwt for any authenticated user
router.post("/:slug/like", checkJwt, async (req, res) => {
  try {
    const { slug } = req.params;
    const userId = req.auth?.sub;

    if (!userId) {
      return res.status(401).json({ error: "Unauthorized", message: "User not found" });
    }

    const userResult = await pool.query(
        'SELECT id FROM users WHERE auth0_id = $1',
        [userId]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: "User not found in database" });
    }

    const dbUserId = userResult.rows[0].id;

    const postResult = await pool.query(
        'SELECT id FROM blog_posts WHERE slug = $1',
        [slug]
    );

    if (postResult.rows.length === 0) {
      return res.status(404).json({ error: "Post not found" });
    }

    const postId = postResult.rows[0].id;

    const existingLike = await pool.query(
        'SELECT id FROM blog_likes WHERE post_id = $1 AND user_id = $2',
        [postId, dbUserId]
    );

    if (existingLike.rows.length > 0) {
      await pool.query(
          'DELETE FROM blog_likes WHERE post_id = $1 AND user_id = $2',
          [postId, dbUserId]
      );
      res.json({ liked: false });
    } else {
      await pool.query(
          'INSERT INTO blog_likes (post_id, user_id) VALUES ($1, $2)',
          [postId, dbUserId]
      );
      res.json({ liked: true });
    }
  } catch (err) {
    console.error("Like error:", err);
    res.status(500).json({ error: "Failed to process like" });
  }
});

// Post a comment - using checkJwt for any authenticated user
router.post("/:slug/comments", checkJwt, async (req, res) => {
  try {
    const { slug } = req.params;
    const { content, parent_id } = req.body;
    const userId = req.auth?.sub;

    if (!userId) {
      return res.status(401).json({ error: "Unauthorized", message: "User not found" });
    }

    // Validate content length (75 words max ~ 525 characters)
    if (!content || content.trim().length === 0) {
      return res.status(400).json({ error: "Comment content is required" });
    }

    const trimmedContent = content.trim();
    const wordCount = trimmedContent.split(/\s+/).length;
    if (wordCount > 75) {
      return res.status(400).json({ error: "Comment must be 75 words or less" });
    }

    const userResult = await pool.query(
        'SELECT id, first_name, last_name, role FROM users WHERE auth0_id = $1',
        [userId]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: "User not found in database" });
    }

    const user = userResult.rows[0];
    const dbUserId = user.id;

    const postResult = await pool.query(
        'SELECT id FROM blog_posts WHERE slug = $1',
        [slug]
    );

    if (postResult.rows.length === 0) {
      return res.status(404).json({ error: "Post not found" });
    }

    const postId = postResult.rows[0].id;

    if (parent_id) {
      const parentComment = await pool.query(
          'SELECT id FROM blog_comments WHERE id = $1 AND post_id = $2',
          [parent_id, postId]
      );
      if (parentComment.rows.length === 0) {
        return res.status(400).json({ error: "Invalid parent comment" });
      }
    }

    const is_approved = user.role === 'Administrator' || user.role === 'Provider';

    const { rows } = await pool.query(
        `INSERT INTO blog_comments 
        (post_id, user_id, content, parent_id, is_approved) 
       VALUES ($1, $2, $3, $4, $5)
       RETURNING *`,
        [postId, dbUserId, trimmedContent, parent_id || null, is_approved]
    );

    const comment = rows[0];
    comment.user_name = formatUserName(user.first_name, user.last_name);
    comment.user_avatar = null;

    res.status(201).json({ comment });
  } catch (err) {
    console.error("Comment error:", err);
    res.status(500).json({ error: "Failed to add comment" });
  }
});

// Get comments for a post - requires authentication
router.get("/:slug/comments", checkJwt, async (req, res) => {
  try {
    const { slug } = req.params;

    const postResult = await pool.query(
        'SELECT id FROM blog_posts WHERE slug = $1',
        [slug]
    );

    if (postResult.rows.length === 0) {
      return res.status(404).json({ error: "Post not found" });
    }

    const postId = postResult.rows[0].id;

    const { rows } = await pool.query(
        `SELECT 
        bc.*,
        u.id as user_id,
        u.first_name,
        u.last_name
       FROM blog_comments bc
       LEFT JOIN users u ON bc.user_id = u.id
       WHERE bc.post_id = $1 AND bc.is_approved = true
       ORDER BY bc.created_at ASC`,
        [postId]
    );

    const formattedComments = rows.map(comment => {
      const formattedName = formatUserName(comment.first_name, comment.last_name);
      return {
        ...comment,
        user_name: formattedName,
        user_avatar: null,
      };
    });

    const commentsWithReplies = buildCommentTree(formattedComments);
    res.json({ comments: commentsWithReplies });
  } catch (err) {
    console.error("Get comments error:", err);
    res.status(500).json({ error: "Failed to load comments" });
  }
});

// ==================== ADMIN ROUTES ====================
router.use(checkJwt);
router.use(attachAdminUser);
router.use(requireAdmin);

// GET route for admin to list posts
router.get("/admin/posts", async (req, res) => {
  try {
    const { status, category, limit = 50, offset = 0 } = req.query;

    let whereClause = "WHERE 1=1";
    const params = [];
    let paramIndex = 1;

    if (status) {
      whereClause += ` AND bp.status = $${paramIndex}`;
      params.push(status);
      paramIndex++;
    }

    if (category) {
      whereClause += ` AND LOWER(bp.category) = LOWER($${paramIndex})`;
      params.push(category);
      paramIndex++;
    }

    const postsQuery = `
      SELECT 
        bp.*,
        u.id as author_id,
        CONCAT(u.first_name, ' ', u.last_name) as author_name,
        '' as author_avatar,
        (
          SELECT COUNT(*) 
          FROM blog_likes bl 
          WHERE bl.post_id = bp.id
        ) as like_count,
        (
          SELECT COUNT(*) 
          FROM blog_comments bc 
          WHERE bc.post_id = bp.id AND bc.is_approved = true
        ) as comment_count
      FROM blog_posts bp
      LEFT JOIN users u ON bp.author_id = u.id
      ${whereClause}
      ORDER BY bp.created_at DESC
      LIMIT $${paramIndex} OFFSET $${paramIndex + 1}
    `;

    const countQuery = `SELECT COUNT(*) FROM blog_posts bp ${whereClause}`;

    params.push(parseInt(limit), parseInt(offset));

    const [postsResult, countResult] = await Promise.all([
      pool.query(postsQuery, params),
      pool.query(countQuery, params.slice(0, -2))
    ]);

    const total = parseInt(countResult.rows[0].count);

    res.json({
      posts: postsResult.rows,
      pagination: {
        total,
        limit: parseInt(limit),
        offset: parseInt(offset),
        hasMore: parseInt(offset) + postsResult.rows.length < total
      }
    });
  } catch (err) {
    console.error("Admin get posts error:", err);
    res.status(500).json({ error: "Failed to load posts" });
  }
});

// CREATE new post
router.post("/admin/posts", upload.single('cover_image'), async (req, res) => {
  try {
    const { title, content_md, excerpt, status, is_featured, category } = req.body;
    const author_id = req.user.id;

    if (!title || !content_md) {
      return res.status(400).json({
        error: "Title and content are required"
      });
    }

    const slug = await generateUniqueSlug(title);
    let cover_image_url = null;

    if (req.file) {
      cover_image_url = `/uploads/blog/${req.file.filename}`;
    }

    const isFeaturedBoolean = is_featured === 'true' || is_featured === true;

    const validStatuses = ['draft', 'published', 'archived'];
    const finalStatus = validStatuses.includes(status) ? status : 'draft';

    const publishedAtValue = finalStatus === 'published' ? 'NOW()' : 'NULL';

    const { rows } = await pool.query(
        `INSERT INTO blog_posts 
        (title, slug, content_md, excerpt, cover_image_url, 
         author_id, status, is_featured, category, published_at, created_at, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7::post_status, $8, $9, ${publishedAtValue}, NOW(), NOW())
       RETURNING *`,
        [
          title,
          slug,
          content_md,
          excerpt || null,
          cover_image_url,
          author_id,
          finalStatus,
          isFeaturedBoolean,
          category || null
        ]
    );

    res.status(201).json({ post: rows[0] });
  } catch (err) {
    console.error("Create post error:", err);
    res.status(500).json({
      error: "Failed to create post",
      details: err.message,
      code: err.code
    });
  }
});

// UPDATE existing post
router.put("/admin/posts/:id", upload.single('cover_image'), async (req, res) => {
  try {
    const { id } = req.params;
    const { title, content_md, excerpt, status, is_featured, category } = req.body;

    const existingPost = await pool.query(
        'SELECT * FROM blog_posts WHERE id = $1',
        [id]
    );

    if (existingPost.rows.length === 0) {
      return res.status(404).json({ error: "Post not found" });
    }

    const validStatuses = ['draft', 'published', 'archived'];
    const finalStatus = status && validStatuses.includes(status) ? status : existingPost.rows[0].status;

    const updateData = {
      title: title || existingPost.rows[0].title,
      content_md: content_md || existingPost.rows[0].content_md,
      excerpt: excerpt !== undefined ? excerpt : existingPost.rows[0].excerpt,
      status: finalStatus,
      is_featured: is_featured !== undefined ? (is_featured === 'true' || is_featured === true) : existingPost.rows[0].is_featured,
      category: category || existingPost.rows[0].category
    };

    if (title && title !== existingPost.rows[0].title) {
      updateData.slug = await generateUniqueSlug(title);
    }

    if (req.file) {
      updateData.cover_image_url = `/uploads/blog/${req.file.filename}`;

      if (existingPost.rows[0].cover_image_url) {
        const oldImagePath = path.join(__dirname, '..', existingPost.rows[0].cover_image_url);
        if (fs.existsSync(oldImagePath)) {
          fs.unlinkSync(oldImagePath);
        }
      }
    }

    const published_at = finalStatus === 'published' && existingPost.rows[0].status !== 'published'
        ? 'NOW()'
        : 'published_at';

    const { rows } = await pool.query(
        `UPDATE blog_posts 
       SET title = $1, 
           slug = COALESCE($2, slug),
           content_md = $3,
           excerpt = $4,
           cover_image_url = COALESCE($5, cover_image_url),
           status = $6::post_status,
           is_featured = $7,
           category = $8,
           published_at = ${published_at},
           updated_at = NOW()
       WHERE id = $9
       RETURNING *`,
        [
          updateData.title,
          updateData.slug,
          updateData.content_md,
          updateData.excerpt,
          updateData.cover_image_url,
          updateData.status,
          updateData.is_featured,
          updateData.category,
          id
        ]
    );

    res.json({ post: rows[0] });
  } catch (err) {
    console.error("Update post error:", err);
    res.status(500).json({ error: "Failed to update post" });
  }
});

// DELETE post
router.delete("/admin/posts/:id", async (req, res) => {
  try {
    const { id } = req.params;

    const existingPost = await pool.query(
        'SELECT cover_image_url FROM blog_posts WHERE id = $1',
        [id]
    );

    if (existingPost.rows.length === 0) {
      return res.status(404).json({ error: "Post not found" });
    }

    if (existingPost.rows[0].cover_image_url) {
      const imagePath = path.join(__dirname, '..', existingPost.rows[0].cover_image_url);
      if (fs.existsSync(imagePath)) {
        fs.unlinkSync(imagePath);
      }
    }

    await pool.query('DELETE FROM blog_comments WHERE post_id = $1', [id]);
    await pool.query('DELETE FROM blog_likes WHERE post_id = $1', [id]);
    await pool.query('DELETE FROM blog_posts WHERE id = $1', [id]);

    res.json({ success: true });
  } catch (err) {
    console.error("Delete post error:", err);
    res.status(500).json({ error: "Failed to delete post" });
  }
});

// Admin comment management
router.get("/admin/comments", async (req, res) => {
  try {
    const { status = 'pending', page = 1, limit = 20 } = req.query;
    const offset = (page - 1) * limit;

    const query = `
      SELECT 
        bc.*,
        bp.title as post_title,
        bp.slug as post_slug,
        u.email as user_email,
        CONCAT(u.first_name, ' ', u.last_name) as user_name
      FROM blog_comments bc
      LEFT JOIN blog_posts bp ON bc.post_id = bp.id
      LEFT JOIN users u ON bc.user_id = u.id
      WHERE bc.is_approved = $1
      ORDER BY bc.created_at DESC
      LIMIT $2 OFFSET $3
    `;

    const countQuery = `
      SELECT COUNT(*) 
      FROM blog_comments bc 
      WHERE bc.is_approved = $1
    `;

    const { rows } = await pool.query(query, [
      status === 'approved',
      parseInt(limit),
      parseInt(offset)
    ]);

    const { rows: countRows } = await pool.query(countQuery, [
      status === 'approved'
    ]);

    res.json({
      comments: rows,
      pagination: {
        total: parseInt(countRows[0].count),
        page: parseInt(page),
        limit: parseInt(limit),
        pages: Math.ceil(parseInt(countRows[0].count) / parseInt(limit))
      }
    });
  } catch (err) {
    console.error("Get comments error:", err);
    res.status(500).json({ error: "Failed to load comments" });
  }
});

router.patch("/admin/comments/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const { action } = req.body;

    if (!['approve', 'reject', 'delete'].includes(action)) {
      return res.status(400).json({ error: "Invalid action" });
    }

    if (action === 'delete') {
      const { rowCount } = await pool.query(
          'DELETE FROM blog_comments WHERE id = $1',
          [id]
      );

      if (rowCount === 0) {
        return res.status(404).json({ error: "Comment not found" });
      }

      return res.json({ success: true });
    }

    const { rows } = await pool.query(
        `UPDATE blog_comments 
       SET is_approved = $1, updated_at = NOW()
       WHERE id = $2
       RETURNING *`,
        [action === 'approve', id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: "Comment not found" });
    }

    res.json({ comment: rows[0] });
  } catch (err) {
    console.error("Update comment error:", err);
    res.status(500).json({ error: "Failed to update comment" });
  }
});

// Add separate delete route for admin
router.delete("/admin/comments/:id", async (req, res) => {
  try {
    const { id } = req.params;

    const { rowCount } = await pool.query(
        'DELETE FROM blog_comments WHERE id = $1',
        [id]
    );

    if (rowCount === 0) {
      return res.status(404).json({ error: "Comment not found" });
    }

    res.json({ success: true });
  } catch (err) {
    console.error("Delete comment error:", err);
    res.status(500).json({ error: "Failed to delete comment" });
  }
});

module.exports = router;